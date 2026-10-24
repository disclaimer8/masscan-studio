# Masscan на Rust: спецификация порта сканера

Дата: 2026-10-23. Редакция 1. Текст ниже исторический (проект до реализации);
текущий статус реализации и перечень возможностей, привязанные к commit, находятся в §0
[спеки studio](2026-10-23-cross-platform-qt-rust-design.md). Дедупликация реализована
в engine (не в core), VLAN не поддержан, raw I/O только Linux, UI выбран Slint.
Статус на момент написания: проектная спецификация для составления плана реализации. Разрешены
чтение кода, подсчёты и документация; не разрешены Rust-код в репозиториях,
`cargo new`, установка зависимостей, сборка masscan, сетевые сканы, коммиты и push.

Источник исходников: `/Users/denyskolomiiets/masscan`, upstream
github.com/robertdavidgraham/masscan, ветка master, HEAD `8e6b3b0`
(2026-10-05), версия `1.3.9-integration` (`src/masscan-version.h:3`).
`src/` содержит 217 файлов, 60 853 строки C (`wc -l src/*.c src/*.h`).
Лицензия AGPL-3.0 (`LICENSE`). Все ссылки `файл:строка` ниже относятся к этому
клону; утверждения о поведении masscan проверены по коду, а не по памяти.

Сопутствующие документы studio (спека переноса перенесена в эту ветку;
остальные планы лежат в ветке `feat/cross-platform-spikes` и здесь отсутствуют):
действующая спека переноса
[2026-10-23-cross-platform-qt-rust-design.md](2026-10-23-cross-platform-qt-rust-design.md)
(далее «спека studio», ссылки вида «§5.2, стр. 204» означают раздел и строку
того файла), ранняя спека
[2026-10-20-masscan-studio-design.md](2026-10-20-masscan-studio-design.md),
план проверок `2026-10-23-cross-platform-validation.md` (spikes-ветка, не перенесён).
Спека studio этим документом не правится; расхождения вынесены в §11 и §12.

## 1. Цель, допущения, цели, не-цели, анти-цели

### 1.1. Исходный запрос и уточнения пользователя

1. Пользователь спросил «можем переписать masscan на Rust?» и отказался от
   уточняющих вопросов; мотив не назван.
2. Уточнение пользователя: «хочу, чтобы всё было просто на Rust, без всяких
   C, C++ и прочего».
3. Уточнение пользователя о границах: «все все — ну бэкенд». Требование
   распространяется на бэкенд studio, не только на сканер.
4. Сужение пользователя: «nmap оставим и слинт выбираем — но наша задача
   переписать масскан именно». Отсюда три решения:
   - этот документ только о порте masscan на Rust; замена других
     компонентов бэкенда (хранилище, DNS) в него не входит;
   - Nmap остаётся внешним инструментом, как в спеке studio; это осознанное
     исключение из требования «бэкенд на Rust»;
   - UI — Slint; Qt Quick/CXX-Qt отпадает, сравнения прототипов больше нет
     (меняет решение №1 спеки studio).

Это требования и решения пользователя. Всё остальное в этом разделе
помечено как решение или допущение автора спеки.

### 1.2. Допущения автора спеки о мотивах

Мотив не назван, поэтому цели ниже выведены из спеки studio и помечены как
допущения. Каждое проверено на совместимость со спекой studio.

| Допущение | Что в спеке studio это подтверждает | Статус |
| --- | --- | --- |
| Встроить сканер в Rust runner как crate вместо запуска чужого бинарника | §3 стр. 94–96 (runner → внешний masscan), §5.2 стр. 209–214 (проверка хэша/копирование бинарника), §9 стр. 466–479 (матрица версий masscan) — всё это исчезает при движке в процессе | Допущение автора, согласуется с «всё на Rust» |
| Безопасность памяти в коде с правами root/администратора | `VULNINFO.md` upstream прямо называет главной угрозой переполнение буфера от враждебных целей; парсеры баннеров (`proto-*.c`, 18 433 строки) работают под root | Допущение автора |
| Собственная Pause/Resume на Windows без консольных сигналов | §6 стр. 367–376: upstream ловит SIGINT через CRT `signal()` (`src/main.c:1338`), CTRL_C_EVENT нельзя адресовать; прототип B — блокер трёх ОС | Допущение автора, снимает блокер B |
| Единая сборка без C-тулчейна на трёх ОС | Прямо следует из требования пользователя 1.1.2 | Требование |

### 1.3. Цели

1. Rust-движок сканирования с поведением, эквивалентным masscan в части,
   нужной studio: SYN-скан IPv4 TCP, порядок обхода, cookie, троттлинг,
   checkpoint/resume (§4 спеки studio, стр. 124–146).
2. Движок встраивается в Rust runner studio как библиотека; CLI — тонкая
   обёртка для дифференциального тестирования против C masscan.
3. Порт и его зависимости без C/C++: ни `build.rs` с `cc`, ни `-sys` crates,
   компилирующих C, ни обязательной libpcap. Исключения — только ядро ОС, системные
   библиотеки ОС и на Windows драйвер Npcap с его DLL, загружаемой динамически
   (§6.3).
4. Проверяемость: побайтовое совпадение генерации целей и пакетов с C masscan
   в офлайне до первого реального пакета (§7, §9 этап 1).

### 1.4. Не-цели

- Полный drop-in порт CLI masscan, всех 11 форматов вывода, Lua-скриптов,
  PF_RING, `--readscan`/binary-формата, vuln-check, ARP/NDP-сканов,
  IPv6-сканирования как функции studio (IPv6 не входит в v1 studio, §2
  стр. 77). Это отложено, см. §3.
- UI, хранилище, DNS, определение сервисов: UI выбран пользователем (Slint),
  Nmap остаётся внешним по решению пользователя, хранилище и DNS решаются
  отдельными документами (§11).
- Превышение скорости C masscan. Паритет pps на уровне ±20 % при 100–100 000
  pps достаточен (studio ограничивает rate 1…10 000 000, §4 стр. 127).
- Публичный выпуск, подпись, установщики (спека studio §9 стр. 504–509).

### 1.5. Анти-цели (что сделает проект провальным даже при работающем коде)

1. Порядок целей или байты пакетов отличаются от C masscan при одном seed:
   теряется возможность дифференциальной проверки и совместимость resume-index
   с историей studio (§6 спеки studio, стр. 315–325).
2. Появление C/C++ в цепочке сборки «по умолчанию» (например, зависимость с
   `cc` в `build.rs`), даже если код работает.
3. Парсеры баннеров под root без fuzzing: воспроизводят класс ошибок, ради
   устранения которых затевается порт (ср. upstream-коммит `c2d6bf4`
   «fix(smb): prevent OoB read leading to segfault» в `git log`).
4. Pause, которая не доказана тем же способом, что требует план проверок B
   (продолжение исходной последовательности, не рестарт).
5. Нарушение AGPL-3.0 при любом распространении (§8).

## 2. Сравнение подходов

| Подход | Суть | Оценка трудоёмкости | Вердикт |
| --- | --- | --- | --- |
| A. Полный drop-in порт | CLI, `.conf`, все форматы вывода, все протоколы, PF_RING, Lua | 61 тыс. строк C → ~35–45 тыс. строк Rust; 9–14 человеко-месяцев | Отклонён: 60 % объёма (баннеры, форматы, Lua, PF_RING) не нужны studio; совместимость CLI не является требованием |
| **B. Rust-движок как библиотека + тонкий CLI** | Только нужное studio, строгий паритет ядра, парсеры баннеров по мере надобности | Этап 1–3 (§9): ~12–18 тыс. строк Rust, 3–5 человеко-месяцев до интеграции в studio | **Рекомендован** |
| C. c2rust-трансляция | Механический перевод в unsafe Rust и постепенный рефакторинг | Трансляция быстрая, но результат — unsafe-C на Rust с `libc`-вызовами; рефакторинг 61 тыс. строк дороже порта по частям | Отклонён как итоговый результат: нарушает требование 1.1.2 по духу (unsafe-транслят) и тянет C-заголовки. Решение автора: c2rust допустим только как справочный инструмент чтения, если он помогает; в этой спеке не используется |
| D. Оставить C, обернуть через FFI | masscan как static lib, Rust-обёртка | 2–4 недели | Отклонён: прямо противоречит требованию 1.1.2 |

Обоснование B. Движок studio использует узкое подмножество masscan: §4 спеки
studio требует IPv4, CIDR/диапазоны, TCP-порты, исключения, интерфейс, rate,
seed, resume-index, `--echo`-валидацию. Это `main.c` (transmit/receive),
`massip-*`, `crypto-blackrock.c`, `syn-cookie.c`, `main-throttle.c`,
`templ-pkt.c`, `rawsock*`, `stack-arpv4.c`, `main-dedup.c`, `main-conf.c`
(подмножество) — около 14 тыс. строк C. Остальное переносится позже или не
переносится (§3). CLI нужен не для пользователей, а как оракул-двойник для
дифференциальных тестов, поэтому совместимость с CLI masscan ограничивается
опциями, которые участвуют в тестах (§7.1).

## 3. Карта подсистем masscan → модули Rust

Строки — `wc -l` по `src/`. Структура crates (решение автора): workspace
`rmasscan/` с crates `rmasscan-core` (чистая логика, без I/O),
`rmasscan-net` (платформенный raw I/O), `rmasscan-proto` (парсеры баннеров,
подключается опционально), `rmasscan-cli` (тонкий CLI). Имена условные.

| Подсистема masscan | Файлы (строки) | Rust-модуль | Решение |
| --- | --- | --- | --- |
| Разбор целей/исключений, диапазоны IPv4 | `massip.c` 152, `massip-parse.c` 1313, `massip-rangesv4.c` 1389, `massip-addr.c` 353, `main-readrange.c` 106 | `core::targets` | **Порт** в этапе 1. Грамматика: `massip-parse.c:1051` (CIDR, `a-b`, запятые/пробелы), файл `massip-parse.c:822`; порты `massip-rangesv4.c:993` с префиксами `U:`/`S:`/`O:`/`I:` (`:1020–1032`) — переносится только `T:`-подмножество, остальные префиксы отклоняются с ошибкой |
| IPv6-диапазоны | `massip-rangesv6.c` 721 | `core::targets6` | **Отложить**: IPv6 не входит в v1 studio. Индексация в transmit (`main.c:336–358`, IPv6 занимают низкие индексы) учитывается в формуле, чтобы позже добавить без смены порядка |
| BlackRock-перестановка | `crypto-blackrock.c` 420 | `core::blackrock` | **Порт** в этапе 1, побайтово (§4.2). `crypto-blackrock2.c` 573 — не используется transmit (`main.c:261` вызывает `blackrock_init`), только benchmark (`main.c:1792–1793`); **не переносить** |
| SipHash-2-4, SYN-cookie, энтропия | `crypto-siphash24.c` 252, `syn-cookie.c` 171 | `core::cookie` | **Порт** в этапе 1. `get_entropy()` (`syn-cookie.c:18–70`) не переносить: studio задаёт seed явно (§4 стр. 128) |
| LCG | `crypto-lcg.c` 390 | — | **Не переносить**: используется только `--randomize-hosts`-ветками старого кода и selftest; transmit использует BlackRock |
| Троттлер | `main-throttle.c` 163 | `core::throttle` | **Порт** в этапе 1 (§4.5) |
| Transmit/receive-потоки, статус, Ctrl-C, resume | `main.c` 1870, `main-status.c` 292 | `core::scan` (генератор), `engine::tx`, `engine::rx`, `engine::progress` | **Порт**: генератор целей в этапе 1; потоки в этапе 2. Статусная строка stderr (`main-status.c:247`) заменяется типизированными событиями (§10) |
| Шаблоны пакетов | `templ-pkt.c` 1561, `templ-tcp-hdr.c` 1608, `templ-opts.h` 70, `util-checksum.c` 259 | `core::packet` | **Порт** TCP SYN IPv4 в этапе 1 (§4.4). UDP/SCTP/ICMP/ARP-шаблоны, `templ-tcp-hdr.c` (манипуляции TCP-опциями `--tcp-mss` и т.п.) — **отложить**; ARP-шаблон нужен для резолва шлюза (этап 2) |
| UDP-payloads, nmap-payloads | `templ-payloads.c` 905, `templ-nmap-payloads.c` 305 | — | **Не переносить** в v1 (UDP не входит в studio) |
| Собственный TCP-стек, ARP/NDP, очередь передачи | `stack-tcp-core.c` 2314, `stack-tcp-app.c` 219, `stack-arpv4.c` 362, `stack-ndpv6.c` 487, `stack-queue.c` 130, `stack-src.c` 23, `rte-ring.c/h` 1529, `xring.c` 210 | `engine::arp`, `engine::txqueue`; `proto::tcpstack` позже | ARP-резолв шлюза (`stack-arpv4.c:103`) и ответ на входящие ARP — **порт** в этапе 2. TCP-стек для баннеров — **отложить** (этап 4). NDP — не переносить. Lock-free ring — заменить `std::sync::mpsc`/`crossbeam` (pure Rust) |
| Дедупликация, RST-фильтр, таймауты | `main-dedup.c` 466, `misc-rstfilter.c` 194, `event-timeout.c` 176 | `engine::dedup` | Дедуп **порт** в этапе 2 (65536 × 4-way, `main-dedup.c:35–60`); rstfilter и event-timeout — только с TCP-стеком |
| Raw I/O, адаптеры, маршруты | `rawsock.c` 1004, `stub-pcap.c` 458, `stub-pcap.h` 222, `rawsock-getroute.c` 570, `rawsock-getif.c` 495, `rawsock-getip.c` 203, `rawsock-getip6.c` 258, `rawsock-getmac.c` 230, `stub-pfring.c` 105, `rawsock-pcapfile.c` 933 | `net::{linux,macos,windows}`, `net::ifinfo`, `net::pcapfile` | **Порт с заменой механизма** (§6): AF_PACKET/BPF напрямую, без libpcap; Windows — wpcap.dll динамически. PF_RING **не переносить**. Запись pcap-файла (`rawsock-pcapfile.c`) — порт только writer для фикстур (этап 1) |
| Инициализация адаптера (MAC, IP, шлюз) | `main-initadapter.c` 269 | `engine::adapter` | **Порт** в этапе 2 (§4.7) |
| Banner grabbing | `proto-banner1.c` 843, `proto-banout.c` 541, `proto-preprocess.c` 629, `proto-http.c` 952, `proto-ssl.c` 1451, `proto-x509.c` 1392, `proto-smb.c` 2097, `proto-ntlmssp.c` 270, `proto-ssh.c` 205, `proto-ftp/smtp/pop3/imap4/telnet/vnc/rdp/memcached/mc/...` ≈ 3 000, `proto-ssl-test.c` 2432 (тесты), `smack1.c` 1803 (Aho-Corasick), `read-service-probes.c` 1162 | `proto::*` | **Отложить** (этап 4, только если studio закажет `--banners`; определение сервисов остаётся за внешним Nmap по решению пользователя). При переносе — выборочно: HTTP, TLS ClientHello/ServerHello/сертификат, SSH, FTP/SMTP/POP3/IMAP, Telnet, RDP. Проверено: `proto-ssl.c` только формирует ClientHello (`:1077`, `:1115`) и разбирает ServerHello/Certificate/heartbeat; криптографии нет (grep по aes/rsa/hmac даёт только строки-названия шифров `:79–82`). `proto-preprocess.c` (разбор кадров) заменяется crate `etherparse` (§5.2). `read-service-probes.c` — **не переносить** (NPSL, §8.3) |
| Форматы вывода | `output.c` 1022, `out-*.c` 12 файлов ≈ 1 900 | `cli::output` | Studio получает типизированные события (§10). Для CLI-оракула **порт** только list (`out-text.c:38–45`), NDJSON (`out-ndjson.c`) и interactive-строки (`output.c:781`, `:907`). XML/JSON/binary/grepable/unicornscan/redis/certs/hostonly — **не переносить** |
| Чтение бинарных результатов | `in-binary.c` 691, `in-report.c` 397, `in-filter.c` 24 | — | **Не переносить** |
| Конфиг и CLI | `main-conf.c` 3973, `masscan.h` 560 | `cli::args`, `core::config` | **Порт подмножества**: опции из §7.1; `--echo` (`main-conf.c:3636`) как канонический дамп конфигурации для сверки; чтение `paused.conf` (`main-conf.c:3883–3920`) только для импорта чужих checkpoint-файлов (решение автора: не обязателен) |
| Self-tests | вызовы `main.c:1808–1841` (31 selftest) | `#[test]` в соответствующих модулях | **Перенос** тех, чьи модули портируются: `massip_selftest`, `ranges_selftest`, `massip_parse_selftest`, `checksum_selftest`, `siphash24_selftest`, `blackrock_selftest`, `template_selftest`, `dedup_selftest`, `rawsock_selftest`; `templ_tcp_selftest` (`templ-tcp-hdr.c:1531`) — с опциями TCP |
| Скрипты Lua, vuln-check, scripting | `stub-lua.c/h` 270, `scripting*.c` 342, `vulncheck*.c` 184 | — | **Не переносить** |
| Утилиты, потоки, таймеры | `pixie-*.c` ≈ 900, `util-*.c` ≈ 800 | std | Заменить std (`std::thread`, `std::time::Instant`); см. §4.5 о часах |

Итог для этапов 1–3: порт ≈ 14 тыс. строк C; оценка ≈ 10–14 тыс. строк Rust
с тестами.

## 4. Инварианты совместимости

Каждый пункт привязан к коду. Нарушение любого ломает дифференциальное
тестирование или resume-совместимость.

### 4.1. Параметры по умолчанию и пространство индексов

- `blackrock_rounds = 14` (`main.c:1595`), `max_rate = 100.0` (`:1599`),
  `wait = 10` (`:1598`), `is_show_open = 1` (`:1596`), `shard = 1/1`,
  `nic_count = 1` (`:1600–1603`).
- Пространство «портов» объединяет протоколы смещениями:
  TCP 0…65535, UDP +65536, SCTP +131072, ICMP echo 196608, ICMP timestamp
  196609, ARP 196610, Oproto 196864…197119, VulnCheck 262144
  (`massip-port.h:12–23`). Rust-порт обязан сохранить эти смещения в счёте
  индексов, даже если поддерживает только TCP, иначе `range` и индексы
  разойдутся при смешанных списках портов.
- `range = count_ipv4 * count_ports + count_ipv6 * count_ports`
  (`main.c:257–258`); `range_ipv6 = count_ipv6 * count_ports` (`:259`).
  Низкие индексы — IPv6, высокие — IPv4 (`:336`, `:364`).
- Предел 63 бита: `massint128_bitcount(massip_range) > 63` → отказ
  (`main.c:1683–1689`). Для IPv4 × 65536 портов это 48 бит.
- Свыше 1 000 000 000 адресов требуется хотя бы один `--exclude`
  (`main.c:1232–1237`).
- Seed: `--seed N` или `--seed time`; при `seed == 0` берётся энтропия
  (`main-conf.c:2033–2044`, `main.c:1645–1646`). Studio всегда передаёт
  seed в 1…2^32−1 (§4 спеки studio, стр. 128), поэтому ветка энтропии не нужна.

### 4.2. BlackRock (`crypto-blackrock.c`)

- Инициализация (`:109–157`): для `range > 8`: `a = floor(sqrt(range) − 2)`,
  `b = floor(sqrt(range) + 3)` (`:146–147`), затем `while (a*b <= range) b++`
  (`:151`). Для `range ≤ 8` табличные `a,b` (`:118–145`); `range = 0` даёт
  `a = b = 0` (деление на ноль в ENCRYPT; порт должен отвергать пустой range,
  как делает `main.c:1708–1733`).
- Внутренняя функция `READ(r, R, seed)` (`:165–180`):
  `R ^= (seed << r) ^ (seed >> (64 − r))`; затем четыре пары S-box-байтов
  с маской `GETBYTE(R,n) = ((R >> (n*8)) ^ seed ^ r) & 0xFF`, комбинация
  `r0 ^ r1 ^ (r2 << 23) ^ (r3 << 33)`. Сдвиги `seed << r` при `r ∈ 1…14`
  корректны; в Rust использовать `wrapping_shl` только если `rounds ≥ 64`
  (отвергать такие значения).
- ENCRYPT (`:193–216`): `L = m % a; R = m / a`; раунды `j = 1..r`: нечётные
  `tmp = (L + READ(j,R,seed)) % a`, чётные `% b`; затем `L = R; R = tmp`.
  Результат `a*L + R` при нечётном `r`, иначе `a*R + L`. Сложение `L + READ`
  в `uint64_t` может переполняться; порт обязан использовать
  `wrapping_add`, иначе результат изменится.
- `blackrock_shuffle` (`:268–276`): цикл `while (c >= range) c = ENCRYPT(c)`
  (cycle-walking). `unshuffle` (`:282–290`) аналогично с UNENCRYPT (`:221–262`).
- Sbox — 256 байт `crypto-blackrock.c:60–100`; переносится как константа
  и проверяется тестом-хэшем.

### 4.3. Порядок обхода и формула transmit (`main.c:203–498`)

- `start = resume.index + (shard.one − 1) * nic_count + nic_index`;
  `end = range`; при `resume.count` `end = min(end, start + resume.count)`;
  `end += retries * range` (`:270–274`).
- Внутри батча: `xXx = i + (r--) * rate` где `r` стартует с `retries + 1`,
  `rate = (uint64_t)max_rate`; затем `xXx %= range` (если `rate > range`)
  или вычитание range в цикле (`:329–333`); `xXx = blackrock_shuffle(xXx)`
  (`:334`). Следствие, важное для тестов: **при `retries = 0` transmit
  отправляет `shuffle((i + rate) mod range)`, а `-sL` печатает
  `shuffle(i)`** (`main-listscan.c:42`). Порядок одинаков с точностью до
  сдвига на `rate` позиций; дифференциальный тест обязан учитывать это
  (§7.2).
- Индекс `i` увеличивается на `increment = shard.of * nic_count` только когда
  `r == 0` (`:424–427`), то есть после `retries + 1` отправок одной позиции.
- Выбор цели IPv4: `xXx −= range_ipv6; ip = pick(ipv4, xXx % count_ipv4);
  port = pick(ports, xXx / count_ipv4)` (`:364–367`). `rangelist_pick`
  — бинарный поиск по префиксным суммам `picker` (`massip-rangesv4.c:839–873`,
  построение `:884–905`); требует отсортированного и слитого списка
  (`rangelist_sort :258`, `massip_optimize` вызывается в `main.c:1670`).
- Исключения применяются до оптимизации: `massip_apply_excludes`
  (`main.c:1655`), что меняет `count_ipv4` и, значит, все индексы. Порт
  обязан применять исключения в том же месте и с той же семантикой
  (`rangelist_exclude`, `massip-rangesv4.c:730`).
- `parms->my_index = i` после каждого батча (`:433`); главный поток берёт
  `min_index` по потокам (`:1409–1414`) и завершает передачу при
  `min_index >= range` (`:1420–1423`).
- `-sL` считает `end += retries * max_rate` (`main-listscan.c:35`), а не
  `retries * range`; при `retries = 0` различий нет.

### 4.4. Байты пакета (`templ-pkt.c`)

- Шаблон TCP SYN (`:30–55`): Ethernet 14 байт, IPv4 без опций, TTL 255,
  `proto 6`, флаги фрагментации 0, TCP data offset `0x60` (24 байта),
  флаги `0x02`, окно `0x0401` (1024), urgent 0, опция MSS `02 04 05 b4`
  (1460). `templ_tcp_apply_options` (`templ-tcp-hdr.c:1066`) применяется к
  шаблону при `--tcp-mss` и т.п.; по умолчанию без изменений (studio их не
  передаёт).
- Заполнение (`template_set_target_ipv4`, `:877–1095`):
  `ip_id = ip_them ^ port_them ^ seqno` (`:942`), total length, src/dst,
  IP-checksum пересчитывается (`:953–970`); TCP: порты, `seqno = cookie`
  (`:1000–1007`), checksum инкрементально от частичной суммы шаблона
  (`:1009–1018`).
- Cookie (`syn-cookie.c:135–153`): `siphash24(data = [ip_them, port_them,
  ip_me, port_me] как 4 × u32 в порядке байтов хоста, key = [entropy,
  entropy])`, `entropy = masscan->seed` (`main.c:225`). Результат
  усекается до `unsigned` при передаче в шаблон (`main.c:398`). SipHash —
  эталонная реализация Aumasson/Bernstein (`crypto-siphash24.c:1–12`,
  `:128`), совместима с crate `siphasher::sip::SipHasher24::new_with_keys(k0, k1)`
  при записи тех же 16 байт little-endian; совпадение проверяется тестом с
  векторами `siphash24_selftest` (`crypto-siphash24.c:246`). Все три целевые
  платформы little-endian, но порт обязан явно сериализовать `u32::to_le_bytes`.
- Источник: порт по умолчанию `40000 + time(0) % 20000`, диапазон 16
  (`main.c:1316–1321`); при `port_mask != 0` или `ipv4_mask != 0`
  `port_me = src.port + (ck & port_mask)`, `ip_me = src.ipv4 + ((ck >> 16)
  & ipv4_mask)`, где `ck = syn_cookie_ipv4(lo32(i+repeats), hi32(i+repeats),
  lo32(xXx), hi32(xXx), entropy)` (`main.c:373–383`). Для детерминизма тесты
  задают `--source-port N` (диапазон должен быть степенью двойки,
  `main-conf.c:2523–2554`). Studio сегодня `--source-port` не передаёт
  (§4 стр. 129); решение автора: движок studio использует один фиксированный
  порт на попытку, выбранный runner'ом, и сохраняет его в задании.
- Приём: ответ принимается, если `cookie == seqno_me − 1` (`main.c:1058`),
  порт назначения в диапазоне источника (`stack-src.c:17–19`, проверка
  `main.c:934`), дедуп по (ip_them, port_them, ip_me, port_me) (`:1066`);
  SYN-ACK → open, RST → closed (`:1049–1055`); timestamp — `global_now`
  (`:1078`); после отчёта шлётся RST, если нет TCP-стека и не `--noreset`
  (`:1094`).

### 4.5. Троттлер и часы (`main-throttle.c`, `pixie-timer.c`)

- 256 корзин (timestamp, packet_count); скорость считается по разнице с
  корзиной, записанной 256 вызовов назад (`:83–91`); при разрыве > 1 с
  `batch_size = 1` и повтор (`:97–100`); при превышении: ожидание
  `0.1 * (cur − max) / max` с потолком 0.1 с, `batch_size *= 0.999`, повтор
  (`:116–149`); иначе `batch_size *= 1.005`, потолок 10 000 (`:159–163`).
  Стартовый `batch_size = 1` (`:42`). Перенос дословно; тест — симуляция
  с фиктивными часами.
- Часы: macOS `CLOCK_UPTIME_RAW` (`pixie-timer.c:192–194`), иначе
  `CLOCK_MONOTONIC`; Windows QPC (`:58–85`). Rust `std::time::Instant`
  на macOS использует `mach_absolute_time`/`CLOCK_UPTIME_RAW`, на Linux
  `CLOCK_MONOTONIC`, на Windows QPC — семантика «не идёт во сне» на macOS
  совпадает; на Linux `CLOCK_MONOTONIC` не учитывает suspend так же, как в C.
  Поведение после сна покрыто логикой корзин (разрыв > 1 с).

### 4.6. Checkpoint, `paused.conf`, resume

- По SIGINT: `control_c_handler` ставит `is_tx_done` (`main.c:1131–1142`),
  второй Ctrl-C — `is_rx_done`. Главный поток, если `min_index <
  count_ips * count_ports`, записывает `resume.index = min_index` и
  `masscan_save_state` (`:1447–1452`). Запись в **`paused.conf` в текущем
  каталоге** через `masscan_echo(masscan, fp, 0)` (`main-conf.c:395–414`).
- Формат: строки `name = value`; строки, начинающиеся с пунктуации,
  игнорируются (`main-conf.c:3900–3906`); печатаются все параметры из
  таблицы `config_parameters` (`:3636–3651`), `seed` печатается всегда
  (`:2033–2038`), `resume-index` под комментарием `# resume information`
  (`:1922–1933`), затем адаптеры (`masscan_echo_nic :294`), `adapter-port`
  (`:3665–3672`), `ports = …` с префиксами протоколов (`:3677–3716`),
  `range = …` CIDR/диапазоны (`:3721+`). `--resume file` читает файл и
  включает `output-append` (`:2926–2928`).
- Ожидание после остановки: `wait` секунд (`:1491–1493`); через `wait + 10`
  принудительный `exit(0)` (`:1494–1496`).
- Семантика resume-index: индекс `i` в пространстве `0…range` **до**
  перестановки; продолжение с `i` даёт тот же `shuffle((i + rate) mod
  range)`, что и прерванный прогон при тех же seed, targets, ports,
  excludes, rate, retries, shard, rounds. Rate входит в формулу (`:329`),
  поэтому смена rate при resume меняет соответствие индекс → цель. Studio
  фиксирует rate в задании (§6 спеки studio, стр. 317–320), что достаточно.
- Повторы около checkpoint: `min_index` берётся по батчу (`:433`), батч до
  10 000 пакетов; при resume цели от `min_index` до фактического места
  остановки отправляются повторно. Это соответствует «допустимым повторам»
  плана B п. 3.
- `/etc/masscan/masscan.conf` читается на не-Windows до argv
  (`main.c:1628–1636`). Движок на Rust **не читает** системные файлы
  (решение автора); идентичность задания в studio упрощается (§11).

### 4.7. Адаптер, ARP, выбор интерфейса (`main-initadapter.c`)

- Интерфейс по умолчанию — первый с default route
  (`rawsock_get_default_interface`, `:49–57`); MAC — из адаптера или
  `--adapter-mac` (`:97–115`); IP — `rawsock_get_adapter_ip` или
  `--adapter-ip` (`:126–147`); MAC шлюза — `--router-mac`, иначе
  `rawsock_get_default_gateway` + ARP-запрос `stack_arp_resolve`
  (`:177–210`, `stack-arpv4.c:103`); таймаут ARP — ошибка (`:203–209`).
  В `--offline` MAC шлюза фиктивный `66-55-44-33-22-11` (`:160–163`).
  Link-type 0 (NULL/VPN) и 12 (RAW) обходятся без Ethernet (`:87–92`,
  `rawsock.c:795–815`).

### 4.8. Режимы, нужные для проверки

Проверено по `main.c:1700–1850` и `main-conf.c`:

| Режим | Опция | Что делает | Нужны ли права |
| --- | --- | --- | --- |
| Список целей | `-sL` / `--list`… (`main-conf.c:3513`) | Печатает `shuffle(i)` → `ip` или `ip:port` (`main-listscan.c:59–64`); учитывает shard, resume-index/count | Нет |
| Офлайн-передача | `--offline` (алиасы `notransmit`, `nosend`, `dry-run`, `main-conf.c:2384`) | Адаптер без pcap (`rawsock.c:616`), `link_type` остаётся 0 (= DLT_NULL), поэтому шаблон строится без Ethernet, с 4-байтовым заголовком AF_INET (`templ-pkt.c:1342–1351`); пакеты формируются, `rawsock_send_packet` только печатает трассу и возвращает 0 (`rawsock.c:283–299`); rx-поток бездействует (`main.c:742–747`). Годится для бенчмарка генерации | Нет, если задан `--adapter-ip` (MAC при DLT_NULL не нужен, `main-initadapter.c:87–88`) |
| Трасса пакетов | `--packet-trace` | Текст `SENT (t) TCP  [ip]:port > [ip]:port SYN` (`main-ptrace.c:11–108`), **без байтов**. В `--offline` трасса **не печатается**: `packet_trace` разбирает кадр как Ethernet (`main-ptrace.c:30`, `preprocess_frame(..., 1, ...)`), а шаблон в offline — DLT_NULL, ethertype не распознаётся, `preprocess_frame` возвращает 0 и функция выходит (`main-ptrace.c:31–32`, `proto-preprocess.c:63–65`, `:407–408`). Вывод по коду; прогон не выполнялся | — |
| Дамп принятых пакетов | `--pcap FILE` (`main-conf.c:1815–1826`) | Пишет только **принятые** кадры (`main.c:585–587`, `:944–951`); отправленные не пишутся | Да (реальный приём) |
| Чтение pcap как источника | интерфейс `file:path` (`rawsock.c:717–724`) | Приём из файла, конец файла завершает скан (`rawsock.c:358–363`) | Нет; но transmit всё равно нужен адаптер → совместно с `--offline` не работает (offline возвращает до `file:`-ветки). Replay для парсеров делаем в Rust своим harness |
| Эхо конфигурации | `--echo`, `--echo-all`, `--echo-cidr` | Полный дамп параметров в формате `paused.conf` (`main.c:1783–1795`) | Нет |
| Selftest | `--selftest`/`--regress` | 31 модульный тест (`main.c:1808–1841`) | Нет |
| Benchmark | `--benchmark` | BlackRock/smack | Нет |

Следствия: (1) полного байтового дампа отправленных пакетов в C masscan нет;
(2) офлайн-оракула **порядка transmit** (формула `i + r*rate`, retries,
источник-порт) в C masscan тоже нет — `-sL` проверяет только BlackRock,
pick и исключения. Порядок transmit и байты получаем один раз захватом на
изолированном виртуальном интерфейсе (§7.3) и проверяем аналитически по
`main.c:329–334` и шаблону §4.4. Одноразовый запуск готового `bin/masscan
--offline --packet-trace` из клона (не сетевой скан) подтвердит вывод о
пустой трассе; в этой редакции он не выполнялся.

## 5. Платформенный слой

Цели: macOS 14+ Apple Silicon, Windows 11 x64, Ubuntu 24.04 x64. Правило
отбора crates: без `build.rs`, компилирующего C/C++, без `-sys`-crates с
исходниками C, без обязательной libpcap. Документация crates — Context7,
статус — веб-поиск (2026-10-23).

### 5.1. Что делает C masscan сегодня

| Задача | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Передача/приём | libpcap через `dlopen` списка имён (`stub-pcap.c:369–390`), `pcap_create/set_promisc/set_immediate_mode/activate` (`rawsock.c:731–790`); PF_RING опционально | libpcap (`libpcap.A.dylib`), то есть BPF под капотом | `Packet.dll`/`wpcap.dll` из `NPcap\` или PATH через `LoadLibraryA` (`stub-pcap.c:324–352`); sendqueue для скорости (`rawsock.c:827–830`, `:261–271`) |
| Адаптеры | — | — | `GetAdaptersInfo`, имена `\Device\NPF_{GUID}` (`rawsock.c:92–190`), индексы `--iflist` (`:457–505`) |
| Default route/interface | netlink (`rawsock-getroute.c:231–425`, `rawsock-getif.c:179–395`) | `PF_ROUTE`/sysctl (`rawsock-getroute.c:13–230`, `rawsock-getif.c:12–178`) | `GetAdaptersInfo` (`rawsock-getroute.c:426+`, `rawsock-getif.c:396+`) |
| MAC/IP адаптера | ioctl `SIOCGIFHWADDR`/`SIOCGIFADDR` (`rawsock-getmac.c:18–77`, `rawsock-getip.c:20–58`) | `getifaddrs` AF_LINK (`rawsock-getmac.c:158+`, `rawsock-getip.c:147+`) | `GetAdaptersInfo` (`rawsock-getmac.c:78–157`, `rawsock-getip.c:59–146`) |
| Потоки/часы | pthread, `CLOCK_MONOTONIC` | pthread, `CLOCK_UPTIME_RAW` | `_beginthread` (`pixie-threads.c:194`), QPC |
| Линковка | `-lm -lrt -ldl -lpthread`, **без `-lpcap`** (`Makefile:39`) | `-lm -lpthread` | `IPHLPAPI`, `Ws2_32` (`Makefile:64`) |

### 5.2. Предлагаемый слой на Rust

| Задача | Linux | macOS | Windows | Crates (проверка на C) |
| --- | --- | --- | --- | --- |
| Передача/приём | `socket(AF_PACKET, SOCK_RAW)`, `bind` к ifindex, `sendto`/`recv`; опционально `PACKET_TX_RING`/`PACKET_RX_RING` (mmap) на этапе 5 | `open("/dev/bpfN")`, ioctl `BIOCSETIF`, `BIOCIMMEDIATE`, `BIOCSHDRCMPLT`, `BIOCSBLEN`, `BIOCPROMISC`, `BIOCSSEESENT`; `write()` кадра, `read()` буфера с заголовками `bpf_hdr` (выравнивание `BPF_WORDALIGN`) | wpcap.dll через `libloading` (§6.3): `pcap_open_live`/`pcap_create`, `pcap_sendpacket`, `pcap_next_ex`, `pcap_sendqueue_*` для скорости | `libc` (чистые FFI-объявления, без сборки C), `nix` или `rustix` (pure Rust; `rustix` с backend `linux_raw` вовсе не линкует libc для сисколлов), `windows-sys` (сгенерированные объявления; import-библиотеки поставляются как `.lib` в `windows_*` crates, C не компилируется), `libloading` 0.9 (pure Rust) |
| Разбор кадров | `etherparse` (`SlicedPacket::from_ethernet`, zero-alloc, pure Rust) |
| Default route/interface | `rtnetlink`/`netlink-packet-route` (pure Rust) либо чтение `/proc/net/route` | `PF_ROUTE` sysctl через `libc` (порт `rawsock-getroute.c:110–230`) | `GetBestRoute2`/`GetAdaptersAddresses` через `windows-sys` | Альтернатива — crate `net-route` (объединяет три ОС); статус сопровождения проверить при планировании; при сомнении — свой порт C-логики (~500 строк) |
| MAC/IP адаптера | `getifaddrs` через `libc` | то же, AF_LINK | `GetAdaptersAddresses` | `libc`, `windows-sys` |
| ARP шлюза | свой кадр ARP через тот же raw-канал (порт `stack-arpv4.c`) | то же | то же; на Windows возможен `ResolveIpNetEntry2` как запасной путь | — |
| Часы | `std::time::Instant` (§4.5) |
| Потоки | `std::thread`; каналы `std::sync::mpsc` или `crossbeam-channel` (pure Rust) |
| SipHash | `siphasher` 1.x (pure Rust) или 60 строк своей реализации под тест-векторы |
| CLI/сериализация | `clap`, `serde`, `serde_json` (pure Rust) |
| Тесты | `proptest` (pure Rust), `criterion` (pure Rust); fuzzing — см. §7.5 (libFuzzer тянет C++, нужна оговорка) |

Отклонённые crates и причины:

- `pcap` (rust-pcap): линкует libpcap/`wpcap.lib` на этапе сборки (README:
  `LIBPCAP_LIBDIR`, `pkg-config`, на Windows Npcap SDK в `LIB`). Нарушает
  «без обязательной libpcap».
- `pnet`/`pnet_datalink`: Linux AF_PACKET и macOS BPF реализованы на Rust
  (документация `pnet::datalink::linux::channel`, `Config.bpf_fd_attempts`),
  C не компилирует, но Windows-бэкенд линкует `Packet.lib` из WinPcap/Npcap SDK
  на этапе сборки (issue libpnet #646, README default-net). Можно
  использовать как справочный код для Linux/macOS; как зависимость — нет,
  потому что Windows-режим противоречит динамической загрузке и
  `--echo`-валидации без Npcap.
- PF_RING: ядро-модуль и C-библиотека; не переносить.

### 5.3. Зрелость и риски по ОС

| ОС | Механизм | Права | Зрелость | Риски |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 | AF_PACKET | `CAP_NET_RAW` (+`CAP_NET_ADMIN` для promisc); runner через pkexec уже даёт root (§5.1 спеки studio, стр. 173–174) | Высокая: стандартный API, pnet как референс | Скорость `sendto` на пакет ≈ 100–300 kpps; `PACKET_TX_RING` сложнее, но нужен только выше лимитов studio |
| macOS 14+ | `/dev/bpf*` | Устройства `0600 root:wheel`; runner через osascript под root | Средняя: API стабилен, но ioctl-константы нужно взять из SDK-заголовков и сверить; pnet `bpf.rs` — референс | Ограничение буфера BPF (`BIOCSBLEN` до ~4 МБ), потери при высоких pps; VPN-интерфейсы `utun` без Ethernet (link-type NULL, ср. `rawsock.c:803–805`); `BIOCSSEESENT`/direction, чтобы не читать свои пакеты (ср. `rawsock_ignore_transmits`, `rawsock.c:507`) |
| Windows 11 | Npcap + wpcap.dll динамически | Администратор (UAC `runas`, §5.3 спеки studio); Npcap в режиме «Admin only» (§9 стр. 468–470, S11) | Средняя: API libpcap стабилен; FFI-объявления ~40 функций пишем сами по образцу `stub-pcap.h` (222 строки) | Нет Npcap → понятная диагностика без скана (как `stub-pcap.c:333–337`); `pcap_sendqueue_transmit` нужен для > 40 kpps (комментарий `rawsock.c:822–826`); имена `\Device\NPF_{GUID}` (`rawsock.c:853–865`) |

### 5.4. Можно ли на Windows 11 слать TCP SYN без стороннего драйвера

Нет. Документация Winsock «TCP/IP raw sockets» (learn.microsoft.com,
`windows/win32/winsock/tcp-ip-raw-sockets-2`) перечисляет ограничения,
введённые с XP SP2: «TCP data cannot be sent over raw sockets», подделка
UDP-источника запрещена, raw-сокеты требуют группы Administrators. Для
отправки произвольного Ethernet/IP-кадра нужен драйвер: Npcap (NPF) или
WinDivert (тоже драйвер, C). Вывод: на Windows Npcap остаётся неизбежным
исключением (§6.3). Проверка на живой Windows 11 (создание `SOCK_RAW`
с `IPPROTO_TCP` и `sendto`) включена в этап 2 как подтверждение, не как
надежда на обход.

## 6. Сборка без C/C++: правила и исключения

### 6.1. Правила

1. В `Cargo.lock` рабочего пространства нет crates с `cc`, `cmake`,
   `bindgen` (с генерацией во время сборки), `pkg-config`-зависимостями на
   C-библиотеки. Проверяется `cargo tree -e build` и `cargo deny`-правилом
   (pure Rust инструменты) в CI; список запрещённых crates фиксируется.
2. FFI только к системным библиотекам ОС и к DLL, загружаемым через
   `libloading`; объявления пишутся на Rust вручную.
3. Нет `build.rs`, кроме, возможно, встраивания версии.

### 6.2. Проверка выбранных crates (по документации и манифестам на 2026-10-23; перепроверить при фиксации версий)

| Crate | C в сборке | Примечание |
| --- | --- | --- |
| `libc` | нет | Объявления; линкует системную libc |
| `nix`, `rustix` | нет | `rustix` backend `linux_raw` — прямые сисколлы |
| `windows-sys` | нет | import-библиотеки `.lib` поставляются готовыми в `windows_x86_64_msvc`; это не компиляция C |
| `libloading` | нет | — |
| `etherparse`, `siphasher`, `serde`, `serde_json`, `clap`, `crossbeam`, `proptest`, `criterion`, `rtnetlink` | нет | — |
| `pcap` | линковка libpcap | исключён |
| `rustls`/`ring`/`aws-lc-rs` | **да** (C/asm) | Не нужны: TLS-парсер masscan не выполняет криптографию (§3, строка «Banner grabbing»); не добавлять |
| `libfuzzer-sys` | **да** (libFuzzer C++) | только dev-инструмент, §7.5 |

### 6.3. Неизбежные исключения

| Что | Почему без него нельзя | Как загружаем |
| --- | --- | --- |
| Ядро ОС и системные библиотеки (libc/libSystem, kernel32/ws2_32/iphlpapi) | Сисколлы, сокеты, ioctl; Rust std сам на них опирается | Обычная линковка через `libc`/`windows-sys`; C не компилируется |
| Rust toolchain (std, compiler-builtins) | Часть интринсиков std собрана из compiler-rt | Используем официальный toolchain как есть; не считаем нарушением (решение автора) |
| Windows: драйвер Npcap (NPF) и `wpcap.dll`/`Packet.dll` | §5.4: без драйвера Windows не отправляет TCP через raw-сокеты | Пользователь ставит Npcap сам (§9 спеки studio, стр. 466–470); наш код загружает `wpcap.dll` через `libloading` по пути `%SystemRoot%\System32\Npcap\` (как `stub-pcap.c:329`, `:346`), без SDK и без линковки; при отсутствии — диагностика, `--echo`/dry-run работают |
| Внешний Nmap (C++) | Решение пользователя 1.1.4: остаётся внешним инструментом для определения сервисов | Не линкуется и не собирается нами; запускается ядром studio как сейчас (§4 спеки studio, стр. 140–143) |

## 7. Стратегия проверки

Никаких реальных сетевых сканов без отдельного разрешения. Все пункты
ниже либо офлайн, либо на изолированном виртуальном интерфейсе с явным
отдельным разрешением.

### 7.1. Оракул: C masscan

Собирается один раз из клона `8e6b3b0` на Ubuntu-машине (вне этой спеки,
по отдельному разрешению) и фиксируется хэшем. Опции CLI Rust-двойника,
совпадающие по имени и семантике с masscan для тестов: `--seed`, `--rate`,
`-p/--ports`, `--range`/позиционные цели, `--exclude`, `--excludefile`,
`--resume-index`, `--resume-count`, `--shard`, `--retries`,
`--blackrock-rounds`, `--adapter-ip`, `--adapter-mac`, `--router-mac`,
`--source-port`, `--offline`, `--packet-trace`, `-sL`, `--echo`,
`--interface`, `--wait`. Остальные опции masscan не поддерживаются и дают
ошибку (решение автора).

### 7.2. Дифференциальные тесты (офлайн, без прав)

1. **Порядок целей**: `masscan -sL --seed S -p P targets --exclude …` против
   `rmasscan -sL` с теми же аргументами — побайтово одинаковый stdout.
   Матрица: диапазоны 1…10^7 целей, 1…65536 портов, с исключениями,
   режущими диапазоны, shard 1/1, 2/3, resume-index/count, retries 0 и 2
   (помня `end += retries * max_rate` в `main-listscan.c:35`).
2. **Transmit-последовательность**: офлайн-оракула в C нет (§4.8).
   Формула `i + r*rate` (§4.3), retries, resume, shard и выбор
   источник-порта (§4.4) кодируются юнит-тестами, написанными по
   `main.c:270–274`, `:329–334`, `:373–383`, `:424–427` с ручными
   ожидаемыми значениями на маленьких диапазонах (range ≤ 20, rate 1…25,
   retries 0…2), где последовательность выписывается вручную. Сверка с C —
   только golden pcap §7.3 на этапе 2. Rust CLI сохраняет
   `--offline --packet-trace` с рабочей трассой для собственной диагностики.
3. **Echo**: `--echo` обоих даёт одинаковый набор пар `name = value` для
   поддерживаемых параметров (сравнение как множества, порядок не важен).
4. **Чтение `paused.conf`**: фикстуры, снятые с C masscan (из golden
   fixtures studio, §11 спеки studio, стр. 583–585), парсятся Rust-портом в
   ту же конфигурацию.

### 7.3. Байты пакетов

- Юнит-тест: собранный SYN сверяется с ожидаемыми байтами, вычисленными
  из шаблона `templ-pkt.c:30–55` и формул §4.4; checksum проверяется
  независимой реализацией RFC 1071.
- Golden pcap: один раз на Ubuntu-машине C masscan запускается с
  `--interface veth0 --router-mac 66-55-44-33-22-11 --adapter-ip … --rate 10`
  на veth-паре внутри network namespace без маршрута наружу, трафик
  пишется tcpdump; Rust-порт в том же окружении; сравнение кадров без
  Ethernet-временных меток. Требует root и **отдельного разрешения**; это
  не сетевой скан (пакеты не покидают namespace). Фикстура хранится в
  репозитории и используется дальше офлайн.
- Windows и macOS: тот же тест для Rust-порта на loopback-подобном
  интерфейсе (Npcap Loopback Adapter; macOS `feth`/`bridge`) после этапа 2;
  сравнение с golden pcap, а не с живым C masscan.

### 7.4. Перенос self-tests и replay

- Self-tests по §3 переносятся как `#[test]` с теми же входами; для
  `blackrock_selftest` (`crypto-blackrock.c:360–418`) добавляются
  фиксированные seed (в C используется `time(0)`).
- Replay pcap для парсеров баннеров (этап 4): harness читает pcap
  (`data/afl-http.pcap`, `data/flush_all.pcap` из upstream, свои фикстуры),
  прогоняет TCP-поток через парсер и сравнивает banner-вывод с эталоном,
  снятым с C (`--banners` на `file:`-интерфейсе требует transmit; эталон
  снимается через существующие тесты `proto-ssl-test.c` и ручные фикстуры).

### 7.5. Fuzzing

- Парсеры: targets/ports-грамматика, `paused.conf`, разбор кадров (ответы
  SYN-ACK/RST с мусором), позже баннеры. `proptest` для структурных тестов
  (pure Rust). Coverage-guided fuzzing: `cargo-fuzz`/`libfuzzer-sys`
  компилирует libFuzzer (C++). Решение автора: допустить как **dev-only
  инструмент на отдельной машине CI**, не входящий в сборку продукта; если
  пользователь считает это нарушением, запасной вариант — `arbitrary` +
  собственный цикл мутаций на `proptest` (слабее). Вопрос 3 в §12.

### 7.6. Бенчмарки pps

- `--offline` обоих с `--rate 100000000` (как README masscan: `bin/masscan
  0.0.0.0/4 -p80 --rate 100000000 --offline`): скорость генерации; цель
  Rust ≥ 80 % C.
- Реальная передача на veth/loopback (с разрешением): pps при `sendto` и
  при `PACKET_TX_RING`; на Windows с/без sendqueue. Studio нужны 1…10^7 pps
  по валидации, реально — десятки kpps.

## 8. Лицензии

Ниже только то, что прямо следует из текстов лицензий; юридические выводы
о конкретных действиях требуют юриста.

### 8.1. AGPL-3.0 и порт

- Порт, воспроизводящий алгоритмы, константы (S-box, шаблоны пакетов),
  структуру и тексты masscan, — производная работа от AGPL-3.0 программы
  (`LICENSE` в клоне). Авторская позиция: трактовать Rust-порт как
  производную работу и лицензировать его под AGPL-3.0, не пытаться
  доказывать «чистую комнату».
- Личное использование и внутренняя модификация без передачи копий
  обязательств по разделам 4–6 AGPL не создают (разделы 4–6 говорят о
  «conveying»). Раздел 13 (сетевое взаимодействие) касается модифицированной
  версии, с которой пользователи взаимодействуют удалённо по сети; studio —
  локальное приложение, сканируемые хосты не «взаимодействуют с программой
  как пользователи». Это чтение текста, не юридический вывод; нужен юрист,
  если studio когда-либо станет сервисом.
- Любая передача studio третьим лицам (даже бесплатно, даже «закрытый
  бета-тест») с порт-crate внутри — conveying производной работы: исходники
  всей программы, объединённой с AGPL-кодом, должны предоставляться под
  AGPL-3.0 (раздел 5c, 6). Это затрагивает приватность репозитория studio.
  Граница «одна программа или отдельные программы» для in-process crate
  очевидна в сторону «одна программа»; при дочернем процессе (нынешняя
  архитектура) граница спорна. Нужен юрист до любого распространения.
- Уведомления: сохранить копирайт Robert David Graham и упоминание
  источника в каждом портированном модуле (раздел 5a, 7b).

### 8.2. Npcap

- Npcap Free: по странице npcap.com/oem — до пяти установок «с немногими
  исключениями», без права перераспространения, без silent installer;
  условия Free-лицензии «меняются время от времени». Личное использование
  на одной машине пользователя укладывается; перераспространение требует
  OEM Redistribution License. Полный текст лицензии (`npcap.com/license`)
  в этой редакции не прочитан — проверить при планировании этапа 2.
- Мы не распространяем Npcap и не линкуем SDK (§6.3): только динамическая
  загрузка установленной пользователем копии. Это совпадает со спекой studio
  §9 стр. 500–502.

### 8.3. NPSL (Nmap) и `nmap-service-probes`

- NPSL (nmap.org/npsl, аннотированная версия) считает производной работой
  программу, которая «reads or includes Nmap data files such as
  nmap-service-probes». Поэтому `read-service-probes.c` и опция
  `--nmap-service-probes` (`main-conf.c:1585–1598`) не переносятся
  (решение автора). Нынешняя интеграция studio с внешним Nmap остаётся по
  решению пользователя и этим документом не рассматривается; условия NPSL
  для неё относятся к спеке studio.

### 8.4. Прочее

- Исходники SipHash — CC0 (`crypto-siphash24.c:1–12`); crate `siphasher`
  — MIT/Apache-2.0. Crates из §5.2 — MIT/Apache-2.0 (проверить `cargo deny`
  при фиксации).
- Slint (royalty-free/GPL) — UI, вне этого документа; см. спеку studio §9.

## 9. Дорожная карта

Оценки — человеко-недели одного опытного Rust/сетевого инженера. Этапы
последовательны; go/no-go в конце каждого.

| Этап | Содержание | Критерий выхода | Go/no-go | Оценка |
| --- | --- | --- | --- | --- |
| 0. Подготовка | Сборка C-оракула на Ubuntu (отдельное разрешение); фиксация хэша; workspace, `cargo deny` без C; CI на трёх ОС без raw-сокетов | CI зелёный, `cargo tree -e build` без C-crates | — | 1 |
| **1. Ядро генерации** | `core::targets` (грамматика, исключения, optimize/pick), `core::blackrock`, `core::cookie`, `core::packet` (TCP SYN), `core::throttle` (с фиктивными часами), `core::config` + `--echo`, CLI `-sL`, `--offline --packet-trace`; перенос self-tests; дифференциальные тесты §7.2 п. 1, 3, 4; юнит-тесты transmit-формулы §7.2 п. 2 и байтов §7.3 | Побайтовое совпадение `-sL` и `--echo` с C на матрице §7.2; selftests перенесены; transmit-формула и байты SYN покрыты тестами по коду; бенчмарк генерации (`--offline`) ≥ 80 % C | No-go, если найден недетерминизм C, который нельзя воспроизвести (например, зависимость от `time(0)` вне документированных мест) | 3–4 |
| 2. Raw I/O и движок | `net::linux` (AF_PACKET), `net::macos` (BPF), `net::windows` (wpcap через libloading), ifinfo/route/ARP, `engine::{tx,rx,dedup,progress}`, Pause/Resume как состояние движка, checkpoint-событие; golden pcap на veth (разрешение); тест §5.4 на Windows | На каждой ОС: SYN уходит на изолированный интерфейс и байты равны golden pcap; SYN-ACK/RST принимаются и дедуплицируются (fake-ответчик в namespace); Pause → точный индекс → Resume продолжает последовательность (трасса) | No-go для Windows, если Npcap-путь не даёт стабильный send/recv; это не отменяет Linux/macOS, но блокирует трёх-ОС v1 как в плане B | 4–6 |
| 3. Интеграция в studio runner | crate-API движка (§10), события, runner без дочернего masscan; `--echo`-валидация → `validate()`; перенос golden fixtures studio; обновление плана проверок B/R | Studio проходит свой паритет §4 на трёх ОС с движком; смерть runner не оставляет сканер (он в том же процессе) | No-go, если движок в одном процессе с runner нарушает модель прав §5 спеки studio (например, понижение прав после открытия сокета невозможно на какой-то ОС) | 3–4 |
| 4. Banner grabbing (необязательный) | Порт TCP-стека `stack-tcp-core.c` и выборочных `proto::*` (HTTP, TLS, SSH, FTP/SMTP/POP3/IMAP, Telnet, RDP) для режима `--banners`; fuzzing; replay pcap | Паритет banner-вывода с C на fixture-наборе; fuzz 24 ч без падений | Выполняется только если studio закажет `--banners` (§12, вопрос 4); Nmap остаётся внешним в любом случае | 4–6 |
| 5. Производительность и укрепление | `PACKET_TX_RING`, Windows sendqueue, BPF-буферы; стресс 1 М результатов | pps ≥ 80 % C на veth; память по §8 спеки studio | — | 2–3 |

Этап 1 даёт проверяемый результат быстро: без прав, без сети, чисто офлайн.
Общая оценка этапов 0–3: 11–15 недель; с этапами 4–5: 17–24 недели.

## 10. Интеграция со studio: контракт runner

### 10.1. Что меняется

| Аспект | Спека studio сейчас | С движком на Rust |
| --- | --- | --- |
| Архитектура | §3 стр. 94–96: runner запускает внешний masscan | runner содержит crate движка; дочернего процесса нет |
| Запуск/валидация | §4 стр. 129–130: argv, `--echo` без прав | `Engine::validate(cfg) -> EffectiveConfig` в процессе ядра (без прав); `Engine::start(cfg)` в runner |
| Прогресс | stderr-строка `rate:…% done… remaining, found=` (`main-status.c:247`), разбор текста | Событие `Progress { index, range, pps, found, elapsed }` раз в 250–1000 мс; coalesce допустим (§8 спеки studio, стр. 446) |
| Результаты | stdout `Discovered open port 80/tcp on 1.2.3.4` (`output.c:781`), частичные строки, CR/LF (§4 стр. 134) | Событие `PortStatus { ip, port, proto, status: Open/Closed, reason: tcp_flags, ttl, ts }`; дедуп в движке (как `main.c:1066`); парсинга текста нет |
| Pause | SIGINT, `paused.conf` в cwd попытки, чтение файла runner'ом (§6 стр. 343–353) | `Engine::pause()` → движок останавливает tx, ждёт `wait`, отдаёт `Checkpoint { scan_id, attempt_id, resume_index, config_hash }` событием; файл не пишется (опционально пишем `paused.conf`-совместимый файл для диагностики) |
| Resume | `--resume-index` в argv | `cfg.resume_index = Some(u64)`; движок проверяет `resume_index < range` и совместимость config_hash |
| Остановка | SIGINT/SIGTERM/SIGKILL по таймеру 8/12 с (§5.2 стр. 222–224); Windows console event (§6 стр. 367–372) | `Engine::stop()` — атомарный флаг, как `is_tx_done`/`is_rx_done`; потоки завершаются ≤ 1 с (батч ≤ 10 000 пакетов при 10^7 pps). Таймеры 8/12 с остаются как внешняя гарантия на случай зависания |
| Смерть runner | §5.4 стр. 270–313: эксперимент, чтобы не осиротел masscan | Сканер — потоки runner; смерть runner = смерть сканера. Эксперимент §5.4 сводится к проверке, что runner умирает при разрыве IPC |
| Права | §5.1–5.2: проверка хэша masscan, копия в приватный каталог | Проверяется только сам runner (уже требуется §5.1 стр. 181–192). Решение автора: открыть raw-канал под root, затем **не** понижать права (BPF/AF_PACKET fd переживут setuid, но ARP/route-запросы и Windows не симметричны) — оценить на этапе 3 |
| Версии инструментов | §9 стр. 471–479: матрица версий masscan | Версия движка = версия runner; матрица остаётся только для Npcap |
| Формат вывода | §9 стр. 486–491: выбор между interactive и `-oL -` | Не нужен |
| Fake masscan в тестах | §11 стр. 586–589 | Fake-адаптер (`net::Adapter` как trait с in-memory реализацией) и fake-ответчик |

### 10.2. API движка (набросок, решение автора)

```text
trait RawAdapter { fn send(&mut self, frame: &[u8]) -> io::Result<()>;
                   fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>>;
                   fn link_type(&self) -> LinkType; fn flush(&mut self) -> io::Result<()>; }
struct ScanConfig { targets, ports, excludes, seed: u64, rate: f64, retries: u32,
                    resume_index: Option<u64>, source_port: u16, adapter: AdapterSpec,
                    wait_secs: u32, blackrock_rounds: u32 /* = 14 */ }
enum Event { Started{range}, Progress{..}, PortStatus{..}, Checkpoint{..},
             Finished{reason: Completed|Paused|Stopped|Failed(err)} }
Engine::validate(&ScanConfig) -> Result<EffectiveConfig, ValidationError>  // без прав
Engine::start(ScanConfig, Box<dyn RawAdapter>, Sender<Event>) -> Handle
Handle::pause(), Handle::stop(), Handle::join()
```

`u64` seed/index остаются u64 внутри Rust; на границе UI — decimal TEXT
(§6 спеки studio, стр. 354–365) без изменений.

## 11. Что меняется в спеке studio

Спека studio не правится; таблица — предмет её следующей редакции.

Статус (2026-10-24): правки ниже применены в редакции 8 спеки studio как
пометки «Ред. 8» (исторический статус внешнего masscan, расширенный приоритет,
решение 10 в §1) и §0.1 с реализованными контрактами engine. Набросок API в §10.2
исторический: фактические типы см. `rmasscan-engine` и §0.1 спеки studio.

| Решение/раздел, строки | Что меняется | Основание |
| --- | --- | --- |
| §3 стр. 85–117 (runner → внешний masscan); §4 стр. 129–134 (argv, `--echo`, разбор stdout/stderr); §5.2 стр. 209–224 (хэш/копия masscan, SIGINT-остановка); §5.4 стр. 270–313 (осиротевший masscan); §6 стр. 322–376 (`/etc/masscan/masscan.conf`, чтение `paused.conf`, Windows console event, прототип B); §9 стр. 471–491 (матрица версий masscan, выбор формата вывода); §11 стр. 586–589 (fake masscan); §12 стр. 613 | Внешний masscan заменяется Rust-движком внутри runner по контракту §10; Pause/Resume, прогресс и результаты — типизированные события; прототип B переформулируется в «Windows Npcap raw I/O + pause движка» (этап 2 §9); остаётся только матрица версий Npcap | Этот документ |
| Решение №1 стр. 12; §3 стр. 109–117; §10.2 стр. 544–557 (A1/A2); план A1 | UI — Slint; Qt Quick/CXX-Qt и сравнение прототипов снимаются | Решение пользователя 1.1.4 |
| §4 стр. 140–143; §9 стр. 466–470, 500 (Nmap) | Nmap остаётся внешним инструментом без изменений | Решение пользователя 1.1.4 (исключение из «бэкенд на Rust») |
| Решение №5 стр. 16; стр. 34; §7 стр. 378–399 | SQLite через rusqlite (`libsqlite3-sys` bundled) компилирует C и конфликтует с требованием 1.1.2; решается отдельным документом, в этот не входит | Требование пользователя 1.1.2 |
| §9 стр. 500 («masscan — AGPL-3.0, не включать бинарники») | Порт — производная работа AGPL-3.0 внутри нашей сборки (§8.1) | Этот документ |

## 12. Открытые вопросы к пользователю

По убыванию важности; ответ меняет то, что строится.

1. Принимается ли AGPL-3.0 для порта внутри приватного studio с
   пониманием, что любая передача studio третьим лицам потребует выдачи
   исходников всей программы под AGPL (§8.1)? Альтернатива — не делать
   порт как производную, а это совсем другой проект.
   **Ответ пользователя (2026-10-23): да, AGPL-3.0 принимается.**
2. Разрешить ли на Ubuntu-машине однократную сборку C masscan (оракул) и
   захват golden pcap в изолированном network namespace (root, без выхода
   пакетов наружу)? Без этого байтовая сверка остаётся аналитической (§7.3),
   а дифференциальные тесты §7.2 — только на уже собранном бинарнике
   `bin/masscan` из клона, происхождение которого не зафиксировано.
   **Ответ пользователя (2026-10-23): да, разрешено** — однократная сборка
   C-оракула и захват golden pcap в изолированном namespace на Ubuntu.
3. Допустим ли `cargo-fuzz` (libFuzzer, C++) как dev-инструмент на
   отдельной CI-машине, не входящий в сборку продукта? (§7.5)
4. Нужен ли режим `--banners` (этап 4, порт TCP-стека и парсеров) в studio,
   если определение сервисов остаётся за Nmap? Без него этапы 0–3 закрывают
   все функции §4 спеки studio.
5. Нужен ли паритет скорости с C выше ~100 kpps (этап 5), учитывая, что
   studio по умолчанию rate 100 и валидирует до 10^7?
6. Источник-порт: сейчас studio не задаёт `--source-port`, и masscan берёт
   16 портов от `40000 + time % 20000` (`main.c:1316–1321`). Движок будет
   выбирать один фиксированный порт на попытку и хранить его в задании
   (решение автора). Подтвердить или оставить 16-портовый диапазон.

## 13. Риски и меры

| Риск | Вероятность/влияние | Мера |
| --- | --- | --- |
| Расхождение порядка целей из-за мелочей (overflow в ENCRYPT, порядок исключений, `end += retries*…`) | Средняя / высокое | Этап 1 целиком посвящён этому; дифференциальная матрица §7.2; `wrapping_*` явно; fuzz-сравнение `-sL` на случайных конфигурациях |
| Нет офлайн-оракула порядка transmit в C; ошибка в формуле `i + r*rate`/источник-порте обнаружится только на golden pcap (этап 2) | Средняя / высокое | Юнит-тесты по коду с ручными ожиданиями (§7.2 п. 2); golden pcap делать первым действием этапа 2; при отказе в разрешении на veth — просить пользователя об одном захвате на его машине |
| Windows: Npcap-путь нестабилен или медленный без sendqueue | Средняя / высокое (блокер трёх ОС, как и B) | Ранний спайк wpcap через libloading на этапе 2; sendqueue в этапе 2, а не 5; явный no-go |
| macOS BPF: потери на приёме, VPN/utun без Ethernet | Средняя / среднее | `BIOCSBLEN` максимум, отдельный rx-поток с большим буфером; link-type NULL/RAW как в `rawsock.c:803–809` |
| Модель прав: движок в runner под root увеличивает TCB по сравнению с дочерним процессом | Высокая / среднее | Rust без unsafe вне `net::*`; `#![forbid(unsafe_code)]` в core/proto; парсеры баннеров под fuzzing до включения; обсудить понижение прав после открытия fd (этап 3) |
| AGPL-3.0 делает приватный репозиторий проблемой при любом распространении | Низкая для личной v1 / высокое при выпуске | §8.1, вопрос 1 в §12; юрист до любого распространения |
| Crate-экосистема вокруг BPF/AF_PACKET мало документирована | Средняя / среднее | Референс — `pnet_datalink` (Rust) и C-код masscan; собственный слой 1–1.5 тыс. строк, покрыт fake-адаптером и golden pcap |
| Недетерминизм C masscan, не покрытый опциями (источник порта по времени, энтропия при seed 0) | Низкая / среднее | Все тесты задают `--seed`, `--source-port`, `--adapter-ip/mac`; расширение списка при обнаружении |
| Объём работы недооценён (парсеры, Windows) | Средняя / среднее | Go/no-go на каждом этапе; studio продолжает работать с внешним masscan до этапа 3 |

## 14. Источники

- Исходники masscan: `/Users/denyskolomiiets/masscan`, HEAD `8e6b3b0`; файлы и строки указаны в тексте. `README.md` (офлайн-бенчмарк, `--echo`), `doc/masscan.8` (`--offline`, `-sL`, `--readscan`), `VULNINFO.md`, `Makefile`, `LICENSE`.
- Спека studio: `docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`; план: `docs/superpowers/plans/2026-10-23-cross-platform-validation.md`; A1: `docs/superpowers/plans/2026-10-23-a1-ui-spikes.md`; `cross-platform/*/Cargo.toml`.
- Context7: `/rust-pcap/pcap` (README: linking, Windows Npcap SDK), `/websites/rs_pnet_pnet` (`datalink::linux::channel`, `Config.bpf_fd_attempts`), `/websites/rs_siphasher_1_0_2` (`SipHasher24::new_with_keys`), `/websites/rs_libloading_0_9_0_libloading` (`Library::new`, `get`), `/websites/rs_etherparse_etherparse` (`SlicedPacket::from_ethernet`).
- Microsoft Learn, «TCP/IP raw sockets»: https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2
- libpnet Windows: https://github.com/libpnet/libpnet/issues/646
- Npcap: https://npcap.com/oem/ , https://npcap.com/oem/redist , https://npcap.com/guide/
- NPSL: https://nmap.org/npsl/npsl-annotated.html
- AGPL-3.0: текст в `LICENSE` клона masscan (разделы 4–6, 13).

## Исправления после этапов 0–1

Поправки к тексту выше, найденные при реализации и ревью этапов 0–1. Где они
противоречат разделам выше, верны эти.

- **(a) criterion не чистый Rust.** Цепочка criterion → alloca → cc тянет C-компилятор,
  поэтому criterion удалён, а бенчмарк это обычный замер времени в цикле
  (`cargo bench -p rmasscan-core`, см. `rmasscan/BENCHMARKS.md`). Неверны строка таблицы в
  §5.2 (стр. ~382, «`criterion` (pure Rust)») и строка в §6.2 (стр. ~438, где
  `criterion` значится без C).
- **(b) C `--offline` на Linux не работает.** На 8e6b3b0 он падает с «bad packet template»:
  proto-preprocess.c:516-531 отвергает AF_INET6=10 (offline-адаптер имеет link type 0, шаблон
  IPv6 пишет 10, а разбор принимает только 24/28/30). Фикстуры `paused/` и замер
  `offline_gen_pps` сняты с копии с правкой в одну строку (link type = Ethernet), хеш в
  `offline_binary_sha256`. Это исправляет §4.8.
- **(c) Диапазон 0 в BlackRock.** В C это бесконечный цикл, а не деление на ноль:
  crypto-blackrock.c:117-120 задаёт `a = b = 0`, после чего `while (a*b <= range) b++` на
  :151-152 не завершается. Исправляет §4.2. В Rust это ошибка `EmptyRange`.
- **(d) `-sL` с retries > 0 в C может зависнуть; Rust это обнаруживает.** В C:
  main-listscan.c:35 удлиняет конец до `range + retries*max_rate`, так что в
  `blackrock_shuffle` попадают индексы `m >= range`, вне области перестановки, и цикл
  `while (c >= range)` (crypto-blackrock.c:268-276) может не завершиться. Rust-путь
  `list_scan`/CLI это обнаруживает и возвращает `ScanError::NonTerminating` до любого
  вывода; зациклиться может только сырой `list_scan_indices` с ручным shuffle-циклом.
  Передача (transmit) безопасна: её конец `range + retries*range` (main.c:273).
- **(e) Осознанные отличия от C.** Порт отвергает: перевёрнутые диапазоны (`10.0.0.5-10.0.0.1`),
  завершающую точку, пустой CIDR, пустой октет и мусор в списке портов (C принимает часть из
  этого молча). Для `range_is_cidr` при `begin == 0` повторено поведение x86 (подтверждено
  оракулом). Вывод `rate` в `--echo` смоделирован по x86 `cvttsd2si` (усечение
  `(unsigned)(max_rate*100000)` по модулю 2^32, main-conf.c:1868). Дополнительно:
  `--seed` обязателен и не равен 0 (в C 0 значит энтропия); `--adapter-ip` принимает один
  адрес (в C диапазон); грамматика `--excludefile` уже, чем у `massip_parse_file` (одна запись
  IPv4/CIDR/диапазон на строку); неизвестные ключи `paused.conf` отвергаются;
  `blackrock_rounds >= 64` отвергается (в C это UB-сдвиг).
- **(f) Запись pcap-файла.** §3 относит pcap-writer к этапу 1. Он не планировался и не
  делался в этапе 1; переносится в этап 2.
