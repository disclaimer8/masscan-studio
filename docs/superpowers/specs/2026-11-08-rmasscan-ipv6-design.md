# rmasscan: IPv6 — проектный документ

**Статус:** проект для плана реализации. Исходник C: `~/masscan/src`, HEAD `8e6b3b0` (read-only). Опоры:
[спека порта](2026-10-23-masscan-rust-port-design.md) §3/§4 (разделение пространства `range_ipv6` + `range_ipv4`),
[спека форматов](2026-11-06-rmasscan-output-formats-design.md) (типы 10/11 в `--readscan`),
[план автоопределения](2026-10-27-rmasscan-autodetect.md) (маршрутный поиск интерфейса и следующего хопа на 3 ОС).

## 1. Намерение

Добавить IPv6 к живому скану `rmasscan` (TCP SYN поверх IPv6): разбор диапазонов/исключений IPv6, 78-байтовый шаблон
TCP SYN поверх IPv6 и `syn_cookie_ipv6`, автоопределение адреса источника и шлюза на Linux/macOS/Windows, резолв MAC
соседа/шлюза через NDP Neighbor Solicitation/Advertisement (`ICMPv6 135/136`), смешанную индексацию v4+v6 без изменения
порядка чистого IPv4 и бинарные записи типов `10`/`11` во всех форматах вывода и `--readscan`.

## 2. Цели, не-цели, анти-цели

**Цели (roadmap-уровень):**
- Разбор целевых и исключаемых диапазонов IPv6 (`Range6List` в `u128`, C-форматирование `ipv6address_fmt` с первым
  `::`, `massip-rangesv6.c`, `massip-parse.c`, `massip-addr.c`).
- Смешанная индексация IPv6 + IPv4 в `transmit` с нулевой регрессией для чистого IPv4 (`main.c:258–260, 336–373`) и
  63-битным пределом диапазона (`main.c:1698–1704`).
- 78-байтовый шаблон TCP SYN поверх IPv6 с контрольной суммой RFC 8200 (`templ-pkt.c:718–803, 1110–1212`) и 128-битный
  `syn_cookie_ipv6` (`syn-cookie.c:155–171`) + приём SYN-ACK/RST поверх IPv6 (`proto-preprocess.c:215–332`).
- Автоопределение исходящего интерфейса, локального IPv6 и следующего хопа по таблице маршрутов ядра на Linux, macOS и
  Windows (`rmasscan-net`).
- NDP (`ICMPv6 135/136`): резолв MAC шлюза/соседа с тем же политическим контрактом и таймаутами, что и ARP для IPv4,
  плюс ответ на входящие Neighbor Solicitation (135) во время скана (`stack-ndpv6.c`).
- Записи типов `10` (Open6) и `11` (Closed6) размером 28 байт в `-oB` / `--readscan` и рендер IPv6-адресов в форматах
  `-oL`, `-oJ`, `-oD`, `-oX`, `-oG`, `-oU`, `-oH` и интерактивной строке (`out-binary.c:103–149`, `in-binary.c:228–276`).

**Не-цели:** баннеры и собственный TCP-стек (`--banners`); UDP/SCTP/ICMPv6 echo-скан поверх IPv6 (ограничиваемся TCP
SYN по IPv6, как это фактически работает стабильно в C без экзотики); физические NIC; туннели (Teredo/6to4),
SLAAC/Router Solicitation вместо маршрутных таблиц ОС и DHCPv6-клиент.

**Анти-цели (что делает этап провальным даже при зелёных тестах):**
- Любое изменение порядка или байтов зондов в чистых IPv4-сканах (когда `count_ipv6 == 0`) — нарушение спеки порта §3/§4.
- Неверный псевдозаголовок IPv6 (`next_header = 6`, 40 байт псевдозаголовка, `payload_len`) или смешение BE/LE в
  `syn_cookie_ipv6` (`hi/lo` в C идут как `u64` на LE).
- Использование стандартного RFC 5952 (`Ipv6Addr::to_string()`) вместо `ipv6address_fmt` C там, где это ломает побайтное
  совпадение `-sL`, `--echo` и текстовых форматов вывода (см. Р4).
- Зависание или пропуск резолва MAC из-за того, что KAME-флаг `fe80::X%en0` на macOS протёк в байты NDP-пакета вместо
  чистого `fe80::X` (`s6_addr[2..4]`).
- Запись `-oB` типа `10`/`11` с неверным полем длины (`26`) или смещением полей, которую не читает C `--readscan`.

## 3. Решения автора (Р-номера)

- **Р1 (индексация v4 + v6, лимит 63 бита и поведение `-sL`):**
  в `transmit` (`~/masscan/src/main.c:258–260, 336–373`) вычисляем `range_ipv6 = count_ipv6 * count_ports`,
  `range_ipv4 = count_ipv4 * count_ports` и `range = range_ipv6 + range_ipv4` (проверяем `range.ilog2() <= 63`, иначе
  отказываем с `[-] FAIL: scan range too large, max is 63-bits...`, `main.c:1698–1704`, так что для одного порта
  максимальная подсеть IPv6 — `/66`). После `x = blackrock_shuffle(i)`:
  - если `x < range_ipv6`, выбираем `ip6 = pick6(x % count_ipv6)` и `port = pick_port(x / count_ipv6)`;
  - иначе `x -= range_ipv6`, `ip4 = pick4(x % count_ipv4)` и `port = pick_port(x / count_ipv4)`.
  При `count_ipv6 == 0` имеем `range_ipv6 == 0`, следовательно **порядок и байты чистых IPv4-сканов не меняются ни на
  бит**. При смешанном скане v4+v6 и ненулевом `range_ipv6` IPv6 занимает нижние индексы `0..range_ipv6`, как в
  `transmit_thread` C — отличие от C: в `-sL` оригинальный `massip.c:24, 30–43` (`massip_pick`) при одновременном
  наличии v4 и v6 инвертирует порядок (`v4` внизу, `v6` вверху); в `list_scan` воспроизводим `massip_pick` для
  побайтного паритета с C `-sL` (формат `[<ip6>]:<port>\n` при `count_ports > 1` и `<ip6>\n` при `1` порте,
  `main-listscan.c:53–63`), явно документируя эту историческую причуду `massip_pick` vs `transmit_thread`, и исправляем
  баг `main.c:1235` (допускаем запуск, когда заданы только IPv6-исключения или диапазон > `1e9`).
- **Р2 (NDP вместо Router Solicitation, форматы кадров и тайминги):**
  вместо нестабильного Router Solicitation (`133 -> 134`) C (`stack-ndpv6.c:312–487`, часто игнорируемого локальными
  стеками и хостами на-link) используем точную связку **маршрут ОС → next-hop IPv6 → NDP Neighbor Solicitation (`135`) →
  Neighbor Advertisement (`136`)**, по образцу ARP-резолвера для IPv4:
  - отправляем 86-байтный Ethernet + IPv6 + ICMPv6 Neighbor Solicitation (`dst_mac = 33:33:ff:XX:XX:XX`, `ethertype =
    0x86DD`, `payload_len = 32`, `next_header = 58`, **`hop_limit = 255`**, `src = source_ipv6`, `dst = ff02::1:ffXX:XXXX`,
    `target = next_hop_ipv6`, ICMPv6 Option `1` Source Link-Layer Address = `source_mac`) с той же политикой повторов и
    таймаутом, что и `ArpPolicy`, отменяемой по первому Ctrl-C;
  - принимаем ответ `ICMPv6 type == 136, code == 0, hop_limit == 255`, matching `target == next_hop_ipv6`, извлекая Option
    `2` Target Link-Layer Address; при наличии явного `--router-mac-ipv6` / `--router-mac` NDP-фаза пропускается;
  - во время самого скана RX-поток отвечает на входящие Neighbor Solicitation (`type 135`) на `source_ipv6` валидным
    86-байтным Neighbor Advertisement с `payload_length = 32` (`stack-ndpv6.c:95–182`, исправлена опечатка `:145`).
  Дополняем CLI алиасом `--router-mac-ipv6` и поддержкой IPv6 в `--adapter-ip` и `--router-ip` (`--router-ipv6`).
- **Р3 (автоопределение source IPv6 на Linux, macOS и Windows):**
  оригинальный `rawsock-getip6.c:68` отбрасывает ULA `fd00::/8` (`fc00::/7`) и документационный `2001:db8::/32` и не
  умеет выбирать адрес по конкретному маршруту, что ломает стенды. По образцу v4-автоопределения (`2026-10-27`) читаем
  таблицу маршрутов IPv6 ядра без отправки пакетов:
  - **Linux:** `AF_NETLINK` `RTM_GETROUTE` с `AF_INET6` и `RTA_DST` первой цели → получаем `RTA_OIF`, `RTA_GATEWAY` и
    `RTA_PREFSRC`, дополняем адресами интерфейса из `RTM_GETADDR` (`AF_INET6`), отбрасывая loopback/tentative/link-local
    при наличии global/ULA;
  - **macOS:** `PF_ROUTE` `RTM_GET` (`sockaddr_in6`) + `getifaddrs` (`AF_INET6`), **обязательно обнуляя встроенный
    KAME `scope_id` в байтах `s6_addr[2..4]` для `fe80::/10`** (на `utun`/VPN действуют те же правила выбора/отказа, что
    в v4-автоопределении);
  - **Windows:** `GetBestRoute2` (`AF_INET6`) + `GetAdaptersAddresses(AF_UNSPEC)` (даёт и `BestSourceAddress`, и
    `NextHop`).
  Разрешаем ULA (`fc00::/7`) и `2001:db8::/32` на запечатанных стендах (отказ только на loopback/multicast/unspecified,
  как для немаршрутизируемых в v4). При смешанном скане v4+v6 интерфейс должен совпадать для обеих семей (явный
  конфликт отклоняется с `exit 1`).
- **Р4 (грамматика целей IPv6 и формат `ipv6address_fmt`):**
  принимаем полную нотацию, `::`-сжатие (ровно один `::`), квадратные скобки `[addr]`, CIDR `/0..128`, диапазоны `a-b` и
  `-6` (как no-op флаг совместимости, `main-conf.c:3323–3325`, `massip-parse.c:274–763`). Исправляем две ошибки C:
  разрешаем необрамлённые IPv6-цели, начинающиеся с `a`–`f` (например `fd00::/64` в позиционном argv, которое C
  отклонял в `main-conf.c:3594`), и отклоняем обратные диапазоны `begin > end`.
  Для текстового вывода (list/json/ndjson/xml/grepable/unicornscan/hostonly/interactive/`-sL`/`--echo`) портируем
  `ipv6address_fmt` (`massip-addr.c:33–109`) в чистом Rust — в C сжимается **первая** встречаемая последовательность
  нулевых 16-битных слов (вплоть до одиночного `:0:`), тогда как RFC 5952 сжимает *самую длинную* серию длиной ≥ 2;
  например `2a03:9060:0:400:0:0:0:2` форматируется как `"2a03:9060::400:0:0:0:2"`. Точный порт `ipv6address_fmt`
  обеспечивает байтовый паритет с C `--readscan` и `-sL` — сознательное сохранение формата C.
- **Р5 (шаблон TCP/IPv6, приём и `-oB` записи `10`/`11`):**
  - 78-байтовый шаблон TCP SYN поверх IPv6 (`templ-pkt.c:718–803, 1110–1212`): 14B Ethernet (`dst = router_mac_ipv6`,
    `ethertype = 0x86DD`), 40B IPv6 (`60 00 00 00`, `payload_len = 24 + extra_tcp_opts`, `next_header = 6`, `hop_limit =
    ttl` [дефолт `255`], 16B `ip_me`, 16B `ip_them`), 24B TCP SYN (`win = 04 01`, MSS `02 04 05 b4` + TCP-опции).
  - `seqno = syn_cookie_ipv6(ip_them, port_them, ip_me, port_me, entropy) as u32` (`syn-cookie.c:155–171`, SipHash-2-4 с
    `k0 = k1 = entropy` по 40 байтам `[ip_them.hi, ip_them.lo, ip_me.hi, ip_me.lo, ((port_them as u32) << 16) as u64 |
    port_me as u64]` в LE; в `transmit_thread` `main.c:345–346` для IPv6 используются фиксированные `src.ipv6` и
    `src.port.first`).
  - На RX (`proto-preprocess.c:215–332`, `main.c:810–838, 1048–1060`) пропускаем optional Hop-by-Hop (`next_header = 0`,
    длина `(ext[1] + 1) * 8`) до TCP (`6`), проверяем `seqno == ackno - 1` и **записываем реальный `hop_limit` из байта
    `offset_ip + 7`** (отличие от C: в `proto-preprocess.c:232–279` автор забыл скопировать `px[offset + 7]` в
    `info->ip_ttl`, поэтому в живом IPv6-скане C печатал `ttl=0`, тогда как в `-oB` байт `10` существует и C
    `--readscan` выводит его правильно).
  - В `-oB` (`out-binary.c:103–149`, `in-binary.c:228–276`) пишем и читаем 28-байтовые записи типов `10` (Open6) и `11`
    (Closed6): `[0: type(10|11), 1: len=26, 2..5: ts BE4, 6: ip_proto=6, 7..8: port BE2, 9: reason, 10: ttl, 11:
    version=6, 12..19: ip.hi BE8, 20..27: ip.lo BE8]`. В XML (`out-xml.c:75`) пишем `addrtype="ipv6"`; `ReadFilter`
    в `--readscan` поддерживает IPv6-диапазоны целей (исправляя баг C `in-filter.c:10` с забытым `count_ipv6s != 0`).

## 4. Инварианты совместимости

- **4.1 Шаблон TCP/IPv6 и `syn_cookie_ipv6`** (`~/masscan/src/templ-pkt.c:718–803, 1110–1212`, `syn-cookie.c:155–171`,
  `util-checksum.c:118–153`): 78 байт по умолчанию, RFC 8200 40-байтовый псевдозаголовок, `seqno` SipHash-2-4 совпадает
  с тестовыми векторами C (включая `DLT_NULL` / `DLT_RAW`). *Проверка:* побайтные юнит-тесты + независимый верификатор
  чексуммы RFC 8200.
- **4.2 Смешанная индексация v4 + v6** (`~/masscan/src/main.c:258–260, 336–373`, `massip.c:24, 30–43`): при
  `count_ipv6 == 0` поток кадров v4 побайтно неизменен; при наличии v4+v6 `transmit` отводит `0..range_ipv6` под IPv6,
  `range_ipv6..range` под IPv4, без пропусков и перекрытий; 63-битный лимит не допускает переполнения. *Проверка:*
  регресс-тест чистого IPv4 против golden-дайджеста + юниты смешанных прогонов против C.
- **4.3 NDP-кадры и KAME scope stripping** (`~/masscan/src/stack-ndpv6.c:95–182`): 86-байтный NS (`135`) с solicited-node
  MAC `33:33:ff:...`, адресом `ff02::1:ff...`, валидной ICMPv6-чексуммой с псевдозаголовком и `hop_limit = 255`;
  валидация NA (`136`); ответ на входящие NS во время скана (`payload_length = 32`). *Проверка:* юниты на байты кадров и
  `FakeAdapter`-резолвер, плюс тест очистки `fe80::1%en0` (`s6_addr[2..4] == 0`).
- **4.4 Записи `10`/`11` и `ipv6address_fmt`** (`~/masscan/src/out-binary.c:103–149`, `in-binary.c:228–276`,
  `massip-addr.c:33–109`): 28-байтовая бинарная запись `type = 10|11`, `len = 26`, `version = 6` + 16-байтный IPv6;
  тексты и `-sL` используют `ipv6address_fmt`; XML использует `addrtype="ipv6"`. *Проверка:* golden `--readscan` через
  C-оракул `8e6b3b0` на закоммиченных `.scan`-входах.
- **4.5 Сохранность `Studio` и v4-этапов:** 6 полей `AdapterBinding`, `ReadyPlan::new` и `canonical_job_bytes` для чисто
  IPv4-заданий не меняются; автоопределение v4 на трёх ОС работает без регрессии.

## 5. Как устроено (на уровне швов)

- `Range6List` (`u128` / `(u64, u64)`), `ipv6address_fmt`, `syn_cookie_ipv6`, `checksum_ipv6`, 78-байтный `Tcp6SynTemplate`,
  смешанная выборка `MassIp` и приёмники IPv6/ICMPv6 NS живут в `rmasscan-core` без I/O и без `unsafe`.
- Маршрутное автоопределение IPv6 на Linux/macOS/Windows и проводной NDP-резолвер (`ndp_resolve.rs`) живут в
  `rmasscan-net` (единственный крейт с `unsafe`, строго с `// SAFETY:`) по аналогии с `discover.rs` и `arp_resolve.rs`.
- Разширение `Record` (`IpAddr` v4/v6), `ipv6address_fmt` в форматтерах и типы `10`/`11` в `readscan.rs` живут в
  `rmasscan-cli`.
- `#![forbid(unsafe_code)]` везде, кроме `rmasscan-net`. Без новых крейтов. Pinned Rust 1.99.1.

## 6. Проверка

- **6.1 Офлайн-паритет с C (CI, три ОС):**
  - Разбор и исключения IPv6, `ipv6address_fmt` (случаи с двумя нулевыми блоками, крайними сжатиями, `::/0`), `-sL`
    (`[addr]:port` vs `addr`), 63-битный предел `/66`.
  - Юниты 78B TCP/IPv6 шаблона, `syn_cookie_ipv6`, `checksum_ipv6`, NDP NS (`135`)/NA (`136`), очистки KAME `scope_id`.
  - Смешанная индексация v4+v6 и явный тест побайтной неизменности чистого v4.
  - Golden `--readscan` через C `8e6b3b0` на записях `10`/`11` (Open6/Closed6) во все 8 форматов вывода + фильтрация по
    IPv6-целям.
- **6.2 Живой паритет (Linux netns с IPv6 на minipc; регрессия Windows VM):**
  - Опциональный режим `wire-lab.sh --suite ipv6` (с включением IPv6 внутри временного netns и адресами ULA
    `fd00:198:18::/64` + link-local шлюзом без утечки во внешнюю сеть):
    1. Автоопределение интерфейса, `source-ipv6` и шлюза на netns-стенде + резолв `router-mac-ipv6` через NDP `135/136`
       (и пропуск NDP при `--router-mac-ipv6`).
    2. Чистый TCP SYN-скан по IPv6: порядок и байты кадров (`ip_id`, `seqno`, `hop_limit`, TCP checksum) против оракула C
       по захвату `.pcap` пира; ответы SYN-ACK/RST в `-oB`/`-oJ`/`-oL`.
    3. Смешанный скан `198.18.0.2-198.18.0.3` + `fd00:198:18::2` с одним `--seed` — проверяет `0..range_ipv6` (IPv6) и
       `range_ipv6..range` (IPv4) и сохранность v4-пакетов.
  - На Windows VM — `windows-suite --plan autodetect` (регрессия) + проверка `GetBestRoute2(AF_INET6)` (офлайн или при
    наличии v6 на стенде); живой Mac feth только при явном окне пользователя.
- **6.3 Регрессия предыдущих этапов:** `autodetect`, `output`, `scan-control`, `protocols` и `Studio` проходят без
  изменений.
- **6.4 GO этапа:** все офлайн-тесты, `clippy -D warnings`, `fmt --check` и `Studio` зелёные на трёх ОС в CI; живой
  `--suite ipv6` и регрессии на Linux и Windows — PASS; итоговое ревью одобрено; CI зелёный на точном HEAD.

## 7. Что оставлено строителю

- Точное внутреннее представление `Ipv6Range` (`u128` или `(u64, u64)`), объединение `TcpTemplate` для v4 и v6 и детали
  структур netlink/`PF_ROUTE` в `rmasscan-net` — при соблюдении замороженного контракта `Studio` и инвариантов 4.1–4.5.

## 8. Отличия от C, которые войдут в README (этап документации)

- **Р1:** в смешанном `transmit` индексы IPv6 идут первыми (`0..range_ipv6`), как в C `main.c:336–373`, но в `-sL`
  сохранён порядок `massip_pick` C (`v4` затем `v6`); скан с одним списком IPv6-исключений (без IPv4) не блокируется
  ошибкой `main.c:1235`.
- **Р2:** автоопределение и шлюз резолвятся через таблицу маршрутов ОС + NDP Neighbor Solicitation (`135 -> 136`) вместо
  Router Solicitation (`stack-ndpv6.c`); добавлены `--router-ip` v6 и правильный `payload_length = 32` в ответах NS.
- **Р3:** разрешены ULA (`fc00::/7`) и документационные (`2001:db8::/32`) адреса для изолированных стендов и локальных
  сетей (C `rawsock-getip6.c:68` их запрещает).
- **Р4:** разрешены необрамлённые IPv6-цели, начинающиеся с `a`–`f`, в позиционном `argv` (`fd00::/64`); сохранено
  C-форматирование `ipv6address_fmt` (сжатие первого нулевого блока).
- **Р5:** на приёме IPv6 записывается реальный `hop_limit` из заголовка пакета (в C `proto-preprocess.c` оставляет
  `ttl = 0`), а `--readscan` корректно фильтрует записи по IPv6-целям (`in-filter.c:10` в C забывал `count_ipv6s`).
