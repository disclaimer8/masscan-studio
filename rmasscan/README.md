# rmasscan

Порт ядра сканера [masscan](https://github.com/robertdavidgraham/masscan) на
чистый Rust. Лицензия: AGPL-3.0-only. Оригинал © Robert David Graham; сверка
ведётся с HEAD `8e6b3b0` (версия `1.3.9-integration`).

Документы:

- спека порта (исторический проект): `../docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`
- спека Studio, **§0 это текущий перечень возможностей и контракты engine** (привязан к commit): `../docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`
- планы этапов 0–2A: `../docs/superpowers/plans/`
- статус этапа 2A: `../docs/experiments/2026-10-23-rmasscan-stage2a.md` (исторический)
- приёмка Linux 2B (wire parity, pause/resume, Stop, скорость): `../docs/experiments/2026-10-23-rmasscan-stage2b-linux.md` (исторический)
- замеры скорости: [BENCHMARKS.md](BENCHMARKS.md)
- golden-фикстуры оракула: [tests/golden/README.md](tests/golden/README.md)

## Команды

```bash
cd rmasscan
cargo test
cargo build --locked --release -p rmasscan-cli
# живой скан (только свои адреса): интерфейс, адрес и MAC источника и шлюз определяются сами
sudo target/release/rmasscan 198.51.100.0/24 -p80,443
# то же обнаружение только чтением: строки [+], ни одного кадра, без привилегий
target/release/rmasscan --offline 198.51.100.0/24 -p80 --seed 1
# интерфейсы и маршруты по умолчанию (свой формат, stdout, без привилегий)
target/release/rmasscan --iflist
# результат в файл: -oL, -oJ, -oD, -oG, -oX, -oB, -oH, -oU и имя файла следующим аргументом, «-» это stdout
sudo target/release/rmasscan 198.51.100.0/24 -p80,443 -oJ scan.json
sudo target/release/rmasscan 198.51.100.0/24 -p80,443 -oB scan.bin --show open,closed
# конвертер без сети и без привилегий: прочитать файл -oB и записать любым форматом
target/release/rmasscan --readscan scan.bin -oX scan.xml
target/release/rmasscan --readscan scan.bin --output-format grepable --output-filename scan.gnmap
# управление сканом: шарды (оба с одним --seed), повторы, ограничение скорости и ожидания после скана
sudo target/release/rmasscan 198.51.100.0/24 -p80,443 --seed 7 --shard 1/2 --retries 2 --rate 1000 --wait 5
# Ctrl-C: пауза, запись paused.conf в рабочий каталог; продолжение с дописыванием файла вывода
sudo target/release/rmasscan --resume paused.conf
# бесконечные проходы до Ctrl-C; два адаптера; файл целей и файл конфигурации; захват входящих кадров
sudo target/release/rmasscan --infinite 198.51.100.0/24 -p80
sudo target/release/rmasscan -c scan.conf -iL targets.txt --adapter[0] eth0 --adapter[1] eth1 --pcap rx.pcap
# поля пакета: TTL, неверная L4-сумма, TCP-опции
sudo target/release/rmasscan 198.51.100.0/24 -p80 --ttl 42 --badsum --tcp-mss 1400 --tcp-wscale 7 --tcp-sackok
# протоколы IPv4: префиксы T:/U:/S:/I:/O: в -p липкие (действуют до следующего); UDP, SCTP INIT и ICMP Echo в одном скане
sudo target/release/rmasscan 198.51.100.0/24 -pT:80,U:53,161,S:2905,I:0
# UDP: -sU сам портов не добавляет, а задаёт префикс по умолчанию для следующего -p и таблицу --top-ports; --udp-ports это -pU:
sudo target/release/rmasscan 198.51.100.0/24 -sU -p53,161 --show open,closed
sudo target/release/rmasscan 198.51.100.0/24 --udp-ports 53,161 --nmap-payloads payloads.txt --pcap-payloads udp.pcap
sudo target/release/rmasscan 198.51.100.0/24 -sU --top-ports 20      # UDP; TCP и UDP вместе: -sS -sU
# SCTP INIT (-sZ даёт префикс S:), ICMP Echo (--ping, синоним --ping-sweep, это -pI:0)
sudo target/release/rmasscan 198.51.100.0/24 -sZ -p2905,2906
sudo target/release/rmasscan 198.51.100.0/24 --ping
# ARP-скан своего сегмента (--arp, синоним --arpscan; шлюз не определяется, с портами не сочетается)
sudo target/release/rmasscan 198.51.100.0/24 --arp -oB arp.bin
target/release/rmasscan --readscan arp.bin -oL arp.txt
# баннеры UDP (подэтап 4a; с портом TCP отказ, TCP-баннеры в 4b): строки «Banner on port …» и записи во всех форматах
sudo target/release/rmasscan 198.51.100.0/24 -pU:53,123,137,161,500,5683,11211 --banners -oB udp.bin
sudo target/release/rmasscan 198.51.100.0/24 -pU:53 --rawudp     # ещё и сырой баннер (вся датаграмма) за каждым ответом
# только баннеры нужных приложений из файла -oB; сертификаты PEM в stdout
target/release/rmasscan --readscan udp.bin --banner-types dns-ver --banner-types snmp -oL dns-snmp.txt
target/release/rmasscan --readscan tls.bin --output-format certs --output-filename certs.json
# IPv6 (только TCP SYN): цель в скобках или CIDR; интерфейс, адрес источника и следующий хоп определяются по таблице маршрутов, MAC хопа разрешает NDP
sudo target/release/rmasscan '[2001:db8::1]' -p80,443
sudo target/release/rmasscan 2001:db8::/120 -p80 -oJ scan6.json
# смешанный скан IPv4 и IPv6 одним запуском (оба семейства обязаны идти одним интерфейсом); IPv6 занимает нижние индексы перестановки
sudo target/release/rmasscan 198.51.100.0/24 2001:db8::/120 -p80
# MAC роутера IPv6 задан явно, NDP пропускается (--router-ipv6 как в C синоним того же MAC, а не адреса)
sudo target/release/rmasscan 2001:db8::/120 -p80 --router-mac-ipv6 02-aa-00-00-00-02
# адрес источника и роутер IPv6 заданы явно; --router-ip принимает и IPv6 (расширение, в C только IPv4), MAC роутера тогда разрешает NDP
sudo target/release/rmasscan 2001:db8::/120 -p80 --adapter-ip 2001:db8::10 --router-ip fe80::1
# записи IPv6 в -oB (типы 10 и 11) и их чтение с фильтром по адресу IPv6
sudo target/release/rmasscan 2001:db8::/120 -p80 -oB scan6.bin --show open,closed
target/release/rmasscan --readscan scan6.bin --range 2001:db8::/124 -oL scan6.txt
cargo run -p rmasscan-cli -- -sL 2001:db8::/126 -p80 --seed 1
cargo run -p rmasscan-cli -- -sL 10.0.0.0/30 -p80,443 --seed 1
cargo run -p rmasscan-cli -- --echo 10.0.0.0/24 -p80 --seed 1
cargo run -p rmasscan-cli -- --offline --packet-trace 10.0.0.0/30 -p80 --seed 1 \
  --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --source-port 40000-40003
cargo run -p rmasscan-cli -- --offline --packet-trace '[2001:db8::1]' -p80 --seed 1 \
  --adapter-ip fd00::1 --adapter-mac 00-11-22-33-44-55 --source-port 40000
```

Без флага операции rmasscan сканирует по IPv4 и IPv6: TCP SYN по обоим семействам, а по IPv4 с префиксами и флагами протоколов (раздел «Команды») ещё UDP, ICMP Echo, SCTP INIT и ARP (по IPv6 только TCP SYN, блок «IPv6» в «Отличиях от masscan»). Порядок: значения по умолчанию (seed, порт источника) →
проверка конфигурации → обнаружение (только чтение таблицы маршрутов и интерфейсов, без привилегий) → строки `[+]` →
ARP (IPv4) и NDP (IPv6) к следующему хопу (ARP пропускается при заданном MAC роутера IPv4, NDP при заданном MAC роутера IPv6; `--router-mac` задаёт оба, как в C) → открытие адаптера → скан. Привилегии нужны только для
открытия адаптера: Linux root или `CAP_NET_RAW`, macOS root или доступ к `/dev/bpf*`, Windows Administrator и
Npcap. В stderr идут строки `[+] interface`, `source-mac`, `source-ip`, `router-ip`, `router-mac`, `seed`,
`source-port` и `[+] finished: <итог>, sent N, replies N, open N` (для IPv6 `source-ip = [адрес]`, `router-ip = [адрес]` и `router-mac-ipv6`, у разрешённого NDP с числом запросов и временем: `router-mac-ipv6 = MAC (ndp: N requests, M ms)`); в stdout строки
`Discovered open port N/tcp on IP` (побайтно как masscan; для других протоколов `N/udp`, `N/sctp`, `0/icmp`, у ARP строка с MAC и OUI; адрес IPv6 без скобок, в форме `ipv6address_fmt` C). Отказ обнаружения или ARP печатается в форме C
(`[-] FAIL: …` и строки `[hint]`), код выхода 1; итог `Completed`/`Stopped` даёт 0, любой другой 1.
`-sL` и `--echo` побайтно совпадают с golden-фикстурами C (для целей IPv6 это эталоны `-sL`; разбор `--echo` для IPv6 сверен со сборкой C встроенным тестом).

Вывод. Форматы `-oL` (list), `-oJ` (json), `-oD` (ndjson), `-oG` (grepable), `-oX` (xml), `-oB` (binary), `-oH`
(hostonly), `-oU` (unicornscan) и `--output-format none` для записей статуса TCP, UDP, SCTP и ICMP (IPv4 и IPv6) побайтно равны masscan `8e6b3b0`
(кроме полей, которые C берёт из часов в момент записи; 170 эталонов C в `tests/golden/formats/`: 74 для TCP, 20 для UDP, SCTP и ICMP, 25 для записей IPv6, типы 10 и 11 и `--readscan` с фильтром по адресу IPv6, и 51 для записей баннеров: типы 9 и 13, устаревшие 3, 4 и 5, `--output-format certs`, формат по умолчанию и `--banner-types`; текст адреса IPv6 C пишет `ipv6address_fmt`, без скобок, а XML с `addrtype="ipv6"`). Записи ARP C `--readscan` не читает, их формат проверен по коду C. `--output-format certs` (буквы `-o` у него нет) печатает каждый баннер блоком PEM в stdout, а в файл только `{finished: 1}`, как C (`src/out-certs.c`). Опции:
`--output-format`, `--output-filename`/`--output-file`, `--append-output`/`--output-append`, `--output-flush`,
`--open`/`--output-show-open`, `--show`, `--noshow`, `--interactive`/`--nointeractive`, `--stylesheet`, `--webxml`,
`--no-stylesheet`, `--status`/`--nostatus`, `--ndjson-status`.
С `-o…` stdout молчит (кроме `--interactive`), иначе идут строки `Discovered …`. `--readscan FILE…` читает файлы `-oB`
(записи статуса TCP, UDP, SCTP и ICMP Echo в IPv4 и IPv6, ARP в IPv4, записи баннеров типов 9 и 13 и устаревших 3, 4 и 5) и пишет их теми же форматами; цели и порты, заданные до него, фильтруют записи, а `--banner-types APP` (синонимы `--banner-type`, `--banner-apps`, `--banner-app`, по одному имени на опцию) оставляет только баннеры этих приложений и не читает записи статуса, как C. На stderr
скан печатает строку статуса masscan (`rate`, `done`, `found`) и стирает её 77 пробелами перед `[+] finished`.
С `--nostatus` строки статуса нет, а после скана в stdout идёт `N milliseconds elapsed`, кроме случая, когда stdout
это файл вывода (`-o… -`): C закрывает его вместе с файлом, и в stdout остаётся только формат. Ctrl-C: первое нажатие
ставит скан на паузу (абзац «Управление сканом» ниже), второе выходит с кодом 1.

Баннеры, подэтап 4a (спека `../docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md`, Р1–Р17; справка
`../docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md`). Пока только UDP: `--banners` разбирает
ответы DNS (53, `dns-ver`), NTP (123, `ntp`), NetBIOS (137, `nbtstat`), SNMP (161, `snmp`), ISAKMP (500, `isakmp`), CoAP
(5683, `coap`), memcached (11211, `memcached`) и ZeroAccess (16464, 16465, 16470, 16471, `zeroaccess`), а у остальных портов
пишет первые 64 байта и сырой баннер (`unknown`), как `handle_udp` C (`src/proto-udp.c:54-132`); парсер выбирается по порту
отправителя, баннеры идут сразу за записью `open udp` своего ответа, с её временем и TTL, во всех форматах вывода и в
строках `Banner on port N/udp on IP: [app] текст`. Парсеры сверены с C-парсерами на 204 случаях (9 248 разделов, эталоны
`tests/golden/udp-banners/`). Опции, все они есть и в файле конфигурации и в `--echo` (порядок argv и файлов как у C,
`src/main-conf.c:1106-1180`, `:1288-1298`, `:1546-1554`):
- `--banners[=bool]` (синоним `--banner`), `--nobanners[=bool]` (синоним `--nobanner`) и `--rawudp[=bool]` (сырой баннер за
  каждым ответом, включает и `--banners`): голый флаг это `true`, следующее слово не забирается; `--rawudp --nobanners`
  оставляет флаг `rawudp`, но баннеров нет (как C);
- `--capture TYPE` и `--nocapture TYPE` (синоним `--no-capture`), `TYPE` это `cert` (по умолчанию включён), `servername`,
  `html`, `heartbleed` или `ticketbleed`: в 4a только разбор и `--echo`, действовать они начнут вместе с TCP-баннерами;
- `--hello-timeout N`: принимается и, как у C, ни на что не влияет (Р1, Р17);
- `--banner-types APP` (для `--readscan`, см. «Вывод») и `--output-format certs`.
Без `--banners` и `--rawudp` датаграммы не разбираются, а вывод и кадры прежние байт в байт.

Управление сканом (спека этапа `../docs/superpowers/specs/2026-11-08-rmasscan-scan-control-design.md`, Р1–Р9).
Принимаются только перечисленные ниже опции, все они есть и в файле конфигурации (`ключ = значение`):
- `--shard ONE/OF` (`1 <= ONE <= OF`; без явного `--seed` печатается предупреждение о необходимости общего seed),
  `--retries N` (`0..=999`), `--wait N|forever` (секунды, по умолчанию 10 с; `forever` это `INT_MAX`, как в C), `--rate`, `--blackrock-rounds`;
- `--resume-index N`, `--resume-count N`, `--resume FILE` (разбирается в своей позиции argv, включает дописывание
  файла вывода, ключи правее файла его переопределяют);
- `--infinite` (проходы заново с `seed + 1` до Ctrl-C);
- `-c`/`--conf`/`--config FILE` и `-iL`/`--includefile FILE` в порядке argv;
- `--adapter[i]`, `--adapter-ip[i]`, `--adapter-mac[i]`, `--router-ip[i]`, `--router-mac[i]`, `--source-port[i]`
  с индексом `0..=7` (без индекса это адаптер 0);
- `--pcap FILE` (синоним `--pcap-filename`);
- `--ttl N` (`1..=255`), `--badsum`, `--noreset[=bool]`, `--tcp-mss [N]` (синоним `--tcpmss`), `--tcp-sackok[=bool]`,
  `--tcp-wscale [N]`, `--tcp-tsecho [N]`.

Первый Ctrl-C (Р4): stderr получает `waiting several seconds to exit...`, передача останавливается, приём продолжается
`--wait` секунд, в рабочий каталог пишется `paused.conf` (строка `saving resume file to: paused.conf`), файл вывода
закрывается с подвалом, итог `[+] finished: Paused`, код 0 (`Completed`, если передача успела закончиться). Второй
Ctrl-C выходит сразу с кодом 1, `paused.conf` к этому моменту уже на диске. `--resume paused.conf` продолжает с
сохранённого места и дописывает файл вывода.

### Отличия от masscan

- `--seed` обязателен для `-sL`, `--echo`, `--offline`; для живого скана берётся из энтропии и печатается
  (`[+] seed = N (entropy)`); 0 запрещён (в C 0 означает случайную энтропию).
- Ошибки целей, портов и значений фатальны (в C ошибка `--range` не фатальна).
- Операции `-sL`, `--echo`/`--echo-all`, `--offline` (с `--packet-trace` или без) и `--iflist`
  взаимоисключающие. `--offline --packet-trace` печатает трассу осознанно, в C она пуста.
- Интерфейс выбирается по маршруту к целям: первая и последняя unicast-цель обязаны идти одним маршрутом
  (masscan: интерфейс маршрута по умолчанию). Маршруты по умолчанию читаются таблицей, не lookup-ом `0.0.0.0`.
- Единственная on-link цель: ARP к самой цели (masscan: к маршрутизатору). Несколько on-link целей идут через шлюз
  по умолчанию интерфейса, как у masscan, а без него отказ с подсказками masscan.
- Порт источника по умолчанию один, `40000 + time % 20000` (masscan: два, {p, p+16}).
- `--iflist` печатает свой формат на stdout (masscan: список `pcap_findalldevs` в stderr).
- Строки `[+]` печатаются всегда (masscan только с `-v`), плюс `seed`, `source-port` и `finished`.
- Ctrl-C (Р4 спеки этапа управления): пауза с `paused.conf`, фазой `--wait` и закрытым подвалом вывода (см. выше);
  при `--nostatus` обратный отсчёт `--wait` не зависает (у C он привязан к печати статуса), итог всегда
  `Paused` с целостным подвалом (у C принудительный выход обрывает подвал). Прежнее ограничение «первое нажатие
  останавливает без ожидания и без `paused.conf`» (Р18 этапа форматов) снято.
- Вывод (спека этапа `../docs/superpowers/specs/2026-11-06-rmasscan-output-formats-design.md`, §4 и §8):
  - `-oR` (redis) и ротация (`--rotate`, `--rotate-dir`, `--rotate-offset`, `--rotate-size`) отказывают с сообщением и
    кодом 1 (Р1). `certs` принимается (записи баннеров, подэтап 4a).
  - Неизвестное значение `--output-format` — ошибка с кодом 1 (C печатает FAIL и продолжает с прежним форматом, Р6).
  - Файл вывода открывается до ARP и до engine; при отказе: `out: could not open file for writing` (или
    `appending`), затем `<файл>: <ошибка ОС>`, код 1, ни одного кадра (Р8). C открывает файл в потоке приёма, уже
    после старта передачи, и успевает отправить кадры; текст ошибки ОС у Rust другой.
  - Формат файла без имени (`--output-format json` один) отказывает до любого кадра двумя строками `[-] ERR:` C
    и кодом 1; C принимает такой запуск и молча отбрасывает все записи (`output.c:799–803`).
  - Время записи — Unix-секунды в момент, когда CLI обрабатывает пачку результатов; без отставания кэша `global_now`
    C (до около 1 с, Р9).
  - Имена сервисов для `-oG` и `-oU` читаются из файла services хоста разбором на чистом Rust (`/etc/services`,
    Windows `%SystemRoot%\System32\drivers\etc\services`), первая запись `порт/tcp`, иначе `unknown`; C зовёт
    `getservbyport`, на хосте с NSS-источником помимо files имена могут разойтись (Р10).
  - Одинаковые байты на всех ОС: `\n` не превращается в `\r\n` на Windows, XML сохраняет свои CRLF; C на Windows
    пишет в текстовом режиме (Р12).
  - `--readscan` читает записи статуса (Р13, расширен этапами протоколов и IPv6): типы 6 и 7 (IPv4) и 10 и 11 (IPv6) с
    протоколом TCP, UDP, SCTP или ICMP (`ip_proto` 6, 17, 132, 1) и тип 8 (ARP, `ip_proto` 0), и записи баннеров 9, 13 и
    устаревшие 3, 4, 5 (подэтап 4a, блок «Баннеры» ниже). Остальное — ошибка с
    кодом 1: тип 12 (ARP IPv6) и устаревшие типы статуса 1 и 2 дают `<файл>: unsupported record type N`, запись типа 6, 7, 10
    или 11 с другим протоколом (в том числе с 0) и запись типа 8 с протоколом не 0 — `<файл>: unsupported record protocol P`. Обрыв посреди записи — `[-] file corrupt` и код 1 (C молча
    останавливается с кодом 0); файл короче 99-байтового заголовка с верным началом `masscan/1.1` — тоже
    `[-] file corrupt` и код 1 (C печатает `[-] <файл>: ` и `strerror(errno)`); пустой файл (0 байт) — сообщение о
    неизвестном формате (C: `feof` до первого `fread` ложно, поэтому 0-байтовый файл доходит до `bytes_read < 'a'+2` и
    печатает `[-] <файл>: ` и `strerror(errno)`, а не `file is empty`); на первом плохом файле чтение прекращается.
    `--seed` при `--readscan` игнорируется.
  - `--json-status` и `--status-json` — отказ при разборе с двумя строками C (`[-] FAIL: … not supported, use --status-ndjson`), код 1 (C печатает их, но `masscan_set_parameter` отбрасывает ошибку, и скан продолжается).
  - `--append-output`/`--output-append` и `--output-flush` принимают голый флаг (= `true`) или `=<bool>`
    (`1/0`, `true/false`, `yes/no`, `on/off`, `enable/disable`) в порядке argv, последнее значение побеждает — как в C.
    `--output-show-open`/`--open`/`--open-only` тоже принимают `=<val>`, но значение игнорируют и всегда ставят
    «только открытые» (как в C, `main-conf.c:1794–1806`). Отличие одно: голый `--output-append` значит `true`, тогда
    как в C `--output-append` не `F_BOOL` и забирает следующий argv как своё значение (`main-conf.c:2410`); одиночным
    флагом там работает только `--append-output`.
  - `--infinite` поддержан (см. ниже); Р14 этапа форматов снят.
  - Флаги вывода и статуса допустимы только со сканом и `--readscan`; с `--echo`, `--echo-all`, `-sL`, `--offline`,
    `--iflist` — отказ `output options apply only to a scan or --readscan`, код 1 (Р19). C печатает ключи вывода в
    `--echo` и создаёт пустой файл при `--offline`.
  - C 8e6b3b0 с `--nostatus` не заканчивает живой скан с `--wait` больше 0 (по умолчанию 10 с) и висит, пока не нажат второй Ctrl-C (он выставляет
    `is_rx_done`, `main.c:1150`), не дойдя до принудительного выхода. Первая
    итерация цикла ожидания проверяет окно ожидания (`main.c:1490–1491`) и принудительный выход (`main.c:1494–1496`),
    пока `--wait` ещё не прошёл, и с `--nostatus` сразу ждёт поток передачи (`pixie_thread_join`, `main.c:1530`);
    тот крутится, пока не выставлен `is_rx_done` (`main.c:470`). Выставить его могли бы только проверка окна во
    второй итерации, которой нет, и ветка статуса (`main.c:1518`), которую `--nostatus` пропускает. rmasscan
    заканчивает скан и печатает `N milliseconds elapsed` в stdout, если stdout не файл вывода (`-o… -`): там, как у
    C, остаётся только формат.
- Управление сканом (спека этапа, §8; каждый пункт принят вживую на Linux или покрыт тестами, отчёт
  `../docs/experiments/2026-11-08-rmasscan-scan-control-acceptance.md`):
  - База возобновления нормализована: `resume-index` в `paused.conf` равен минимуму по неисчерпанным адаптерам
    от `(позиция − смещение адаптера)`, а не сырому индексу, как в C. C при возобновлении с шардами прибавляет смещение
    второй раз и сдвигает поток в чужой класс вычетов (`main.c:1408-1414`, `main.c:269`).
  - Пауза доводит текущую пачку повторов до конца без ограничения скорости; C останавливается посреди пачки и
    досылает её после возобновления.
  - Определённые автоматически `adapter-ip`, `adapter-mac` и `router-mac` в `paused.conf` не пишутся (при возобновлении
    определяются заново); заданные явно `--adapter-*` пишутся. C записывает и определённые значения.
  - Ошибка записи `paused.conf` завершает процесс с кодом 1 после фазы ожидания; нечитаемый файл `--resume` — тоже
    код 1 (C молча продолжает). `paused.conf` сохраняется и на хвостовом участке повторов, где C терял недосланное.
  - `--infinite`: со второго прохода `resume-index` и `resume-count` не действуют, проход идёт по всему диапазону (в C
    метка `main.c:251` стоит до расчёта `:269`, и окно первого прохода повторяется каждый раз). `paused.conf` в
    `--infinite` не пишется (C пишет, `main.c:1447`), `-sL --infinite` отказывает (C зацикливает список), а
    `infinite = false` в файле конфигурации учитывается по порядку argv.
  - `--badsum` по-настоящему портит L4-сумму (в C флаг ничего не делает); если сумма вышла нулевой, пишется 1.
  - `--ttl 0` и `--ttl >= 256` отказывают (C `0` игнорирует, `>= 256` не отвергает).
  - `--tcp-tsecho` принимает полное `u32` (в C терялся старший байт).
  - Несколько адаптеров (`nic_count > 1`): возобновление без потерь, дубли ограничены (не более двух отправок на
    зонд, только в потоке самого адаптера); C ведёт себя так же. При `nic_count = 1` возобновление шлёт ровно остаток
    плана (точное мультимножество).
  - `--offline` поддерживает один адаптер; `-iL` с более узкой грамматикой, чем у C, без чтения stdin.
  - Индекс адаптера больше 7 отказывает (в C переполняется массив `nic[8]`).
  - `--resume-count` завершает скан на усечённом пределе (C зависает в ожидании `range`, `main.c:1425`).
- Протоколы IPv4 (спека этапа `../docs/superpowers/specs/2026-11-08-rmasscan-protocols-ipv4-design.md`, §8 и раздел
  «Изменения по итогам реализации»; принято на Linux (netns и veth), на Windows VM снята только регрессия автоопределения,
  отчёт `../docs/experiments/2026-11-08-rmasscan-protocols-ipv4-acceptance.md`). Ссылки на C это masscan `8e6b3b0`:
  - Контрольная сумма UDP, равная нулю, уходит как `0xFFFF` (RFC 768: ноль в поле значит «суммы нет»); C пишет `0x0000`
    (`templ-pkt.c:278–303` возвращает свёртку, сумму инвертирует вызывающий). Расхождение у одного кадра из 65536,
    остальные байты кадров UDP, SCTP, ICMP Echo и ARP равны C.
  - Приём UDP: ответ принимается, только если отправитель это порт из `U:` задания, адрес входит в цели, а суммы IPv4 и
    UDP верны (политика `Verify`, по умолчанию; нулевое поле суммы UDP допустимо). C принимает любую датаграмму на наш
    адрес и порт (`main.c:909–916`, `proto-udp.c:55–72`). Cookie не проверяют ни C, ни rmasscan.
  - Файлы нагрузок `--nmap-payloads` и `--pcap-payloads` читаются только для скана и `--offline`, для `--echo` файл не
    открывается (C читает и там). Любая ошибка файла отказывает до первого кадра с кодом 1: нет файла, синтаксис
    (`--nmap-payloads <файл>: line N: expected "udp"`), неизвестный порядок байт или тип канала pcap, повреждённый заголовок кадра,
    нагрузка длиннее 2006 байт. C печатает сообщение и сканирует дальше с тем, что успел загрузить. Например,
    комментарий после строки нагрузки (`udp 7 "x" # c`) в обоих разборах это ошибка `expected "udp"` на следующем витке:
    C бросает остаток файла и продолжает скан, rmasscan отказывает.
  - Разбор pcap это подмножество `preprocess_frame`: Ethernet (в том числе с 802.1Q), IPv4 без фрагментов, IPv6 с UDP
    сразу за заголовком; остальные кадры пропускаются. Датаграмма без нагрузки заменяет запись порта, как в C. Нагрузка
    до 2006 байт принимается при загрузке (буфер кадра C 2048 байт, длиннее C режет молча), но кадр, который адаптер не примет, завершает
    скан ошибкой передачи (`TxError`): macOS отказывает кадру длиннее 1514 байт, Windows длиннее 1518; у Linux явной
    проверки длины нет, ошибка `send()` ядра (кроме EAGAIN и EINTR) тоже становится ошибкой передачи.
  - ICMP Echo: ответ принимается только с `code == 0` (C принимает любой код, `proto-icmp.c:117–123`), суммы IPv4 и ICMP
    проверяются (C не проверяет), удалённый адрес и `I:0` обязаны входить в задание.
  - ICMP 3/3 (порт недоступен) проверяется как в C, без cookie (`handle_icmp` сверяет только свой адрес и порт); сверх C
    внутренние адрес и порт должны входить в цели, цитата должна быть целой (C читает за концом кадра при большом IHL,
    `proto-icmp.c:42`). Закрытый порт из ICMP 3/3 теперь попадает в результаты и у скана только TCP (как у C; в прежних
    этапах такого не было).
  - Дедупликация: rmasscan пропускает ответы UDP, SCTP и закрытые порты из ICMP 3/3 через `DedupCache` (ключ: протокол,
    адрес и порт цели, свой адрес и порт, статус), по одной записи на ключ. C печатает каждый такой ответ
    (`proto-udp.c:64`, `proto-sctp.c:160` и `:172`, `proto-icmp.c:182`, `:194`, `:206`), поэтому с `--retries` C даёт по
    строке на каждый ответ. Закрытый порт TCP из ICMP 3/3 rmasscan тоже дедуплицирует, C нет (`proto-icmp.c:182`).
    Echo Reply и ARP дедуплицируются в обоих (`proto-icmp.c:125`, `main.c:901`).
  - SCTP: в C ветка SCTP не завершает обработку, `main.c:920–922` (`handle_sctp(...); break;`) проваливается в
    TCP-путь, и чанк с флагами `0x12` или `0x04` даёт ещё и ложную запись TCP. Это не повторяется. Приём SCTP строже C:
    порт получателя из наших портов адаптера (C сообщает до этой проверки), отправитель и порт из `S:` задания,
    CRC-32C при `Verify`, пакет короче 12 байт отбрасывается. `--packet-trace` для
    SCTP печатает строку C `SENT … UNK … [7]`, потому что в `main-ptrace.c` для SCTP нет ветки.
  - `-pO:…` и `-pI:N`, кроме `I:0` (Echo) и `I:2` (ARP), живой скан и `--packet-trace` отклоняют до первого кадра (C шлёт
    неинициализированный шаблон, `templ-pkt.c:932`); `-sL` и `--echo` принимают все пять префиксов. Верхняя граница
    диапазона `O:` выше 255 (`O:1-300`) отказывает при разборе, C проверяет только начало (`massip-rangesv4.c:1067`).
  - `-sU` как в C (`main-conf.c:3524–3549`, `:3609`): сам портов не добавляет, а задаёт префикс по умолчанию для следующего
    `-p`, для строки `ports =` файла `-c` или `--resume` правее него (C разбирает файл на его месте в `argv`,
    `main-conf.c:2663–2674`; `-sU -c f` с `ports = 53` это `U:53`, `-c f -sU` это TCP 53; так же `-sZ`) и таблицу
    `--top-ports`; `--top-ports N -sU` это только UDP, TCP и UDP вместе дают `-sS -sU`. `-sT` у C печатает
    предупреждение и сканирует SYN (`main-conf.c:3530–3533`), у rmasscan это ошибка разбора. Таблица `--top-ports` взята
    из C как есть (1008 записей, четыре повтора).
  - ARP: `--arp` и `-pI:2` дают скан сегмента, шлюз не определяется, кадры широковещательные (42 байта), с портами
    не сочетается (`FAIL: cannot arpscan and portscan at the same time`, как `main.c:1224–1229`). `--top-ports N`
    с `--arp` (или с `arpscan =` в файле) TCP по умолчанию не добавляет, как C (`main-conf.c:3609–3619`):
    `--arp --top-ports 5` это только `I:2`; `-pI:2 --top-ports 5` (без `--arp`) добавляет TCP, как у C. У C `-pI:2`
    без `--arp` сначала определяет MAC шлюза, а ответы ARP игнорирует, потому что `scan_type.arp = 0` (`main.c:893`);
    rmasscan считает это ARP-сканом. Ответ принимается, как в C, если адрес отправителя входит в цели, а адрес
    назначения (`tpa`) наш: приёмник C отбрасывает кадр с чужим адресом назначения ещё до ветки ARP (`main.c:829–837`,
    `proto-preprocess.c:619–621`, затем `main.c:889–905`), поэтому ответ другому узлу и gratuitous ARP записью не
    становятся. MAC берётся из Ethernet-источника кадра (`proto-arp.c:39`), как в C; кодек строже, чем разбор C
    (аппаратный тип 1, протокол `0x0800`, длины 6 и 4, VLAN игнорируется). MAC найденного соседа в шаблоны TCP, UDP
    и SCTP не подставляется.
  - ARP: `--echo --router-mac X --arp` печатает `X`, а C печатает `ff-ff-ff-ff-ff-ff`: `--arp` у C ставит `router-mac`
    на своём месте в argv (`main-conf.c:1100`) и затирает `--router-mac` левее себя; у rmasscan явный `--router-mac`
    побеждает на любом месте. На проводе разницы нет: запросы ARP всегда широковещательные, живой `[+] router-mac` равен `ff-ff-ff-ff-ff-ff`.
  - Интерактивная строка ARP повторяет C (`output.c:770–778`): `Discovered up port 0/arp on IP (aa:bb:cc:dd:ee:ff) OUI`.
    Таблица OUI это собственная таблица masscan (`output.c:687–737`, 46 записей), перенесена как есть; сторонних баз нет.
  - `[+] finished: …, open N` (у C такой строки нет) считает только открытые порты: записи ARP `up` в `open` не
    входят, ARP-скан пишет `open 0`; ответы Echo (`open`) входят.
  - `--readscan`: читает записи типа 8 (ARP), которых C не читает; фильтр `-p` учитывает протокол (`-p U:53` оставляет
    только UDP 53), а C сравнивает порт без сдвига со сдвинутыми диапазонами (`in-filter.c:14–17`), так что `-p U:53`
    в C не оставляет ничего; запись типа 6 или 7 с `ip_proto` 0 или неизвестным rmasscan отказывает (см. выше), C
    её выводит (`err` или `arp`). Эталонов C для фильтра по порту у не-TCP нет, только по адресу.
  - `--pcap` пишет только кадры TCP (`ip_proto` 6): при сканах UDP, ICMP и ARP в файле один заголовок. C не пишет их тоже
    (ветки `continue`, `main.c:874–919`), но пишет ответы SCTP и других протоколов IP через тот же `break` и проваливание в путь TCP (`main.c:920–925`, затем `:943`).
- IPv6 (спека этапа `../docs/superpowers/specs/2026-11-08-rmasscan-ipv6-design.md`, §8 и раздел «Изменения по итогам
  реализации»; принято на Linux (netns и veth), на Windows VM снята только регрессия автоопределения IPv4, отчёт
  `../docs/experiments/2026-11-08-rmasscan-ipv6-acceptance.md`). Ссылки на C это masscan `8e6b3b0`. Как у C, и это
  проверено на `-sL`, `--echo` и по байтам кадров на проводе: порядок `-sL` (IPv4 ниже, IPv6 выше, `massip.c:24, 30–43`),
  индексы смешанного скана (IPv6 в нижних индексах перестановки, `main.c:258–260, 336–373`), 78-байтовый кадр SYN, cookie,
  `--router-mac` для обоих семейств (`main-conf.c:2587–2600`). Отличия:
  - Подтверждение «хотя бы одно `--exclude`» при более чем 10^9 адресов (`main.c:1204`: IPv4 плюс младшие 64 бита счёта
    IPv6): у C подтверждением служит только исключение IPv4 (`main.c:1235` смотрит `exclude.ipv4`). rmasscan принимает и
    исключение IPv6, но только когда переполнение вызвали цели IPv6, то есть одних целей IPv4 не больше 10^9
    (`--exclude 2001:db8::1` для `2001:db8::/66`); спека этапа (Р1) называла это ошибкой C. Исключение IPv4 подтверждает
    всё, как у C. Без исключений, а также для IPv4-целей свыше 10^9 с одним исключением IPv6 (`0.0.0.0/0 --exclude ::1`)
    отказ с текстом C, так что чисто IPv4-скан ведёт себя ровно как C.
  - Предел диапазона 63 бита (скан, `-sL`, `--echo`, `--readscan`; `main.c:1698–1704`, одиночный порт даёт `/66`): rmasscan
    отказывает всегда, когда число адресов, умноженное на порты, не помещается в 63 бита. C считает размер 128-битным
    `massip_range` и в части случаев молча переполняет его: маркер переполнения `::/0` (`massip-rangesv6.c:500–501`)
    складывается с числом адресов IPv4 с обнулением (`:176`), а умножение на порты теряет перенос (`:177`). Проверено:
    `masscan --echo ::/0 10.0.0.1 -p80` и `--echo 2001:db8::/2 -p1-4` выходят с кодом 0, rmasscan с кодом 1 (`requested is
    128 bits`); `::/0 -p80` и `2001:db8::/48 -p443` отказывают у обоих.
  - Только TCP SYN. Порт `U:`, `S:`, `I:`, `O:` и `--arp` вместе с целью IPv6 живой скан и `--packet-trace` отклоняют до
    первого кадра (`IPv6 targets support only TCP ports…`, код 1); `-sL`, `--echo` и `--offline` без трассы их
    принимают. C шлёт по IPv6 и UDP, SCTP и ICMP Echo (`templ-pkt.c:679–701`); перенос отложен.
  - `--ttl` на IPv6 не действует, hop limit всегда 255: `template_set_ttl` правит только шаблон IPv4
    (`templ-pkt.c:1473–1488`). `--badsum` портит и TCP-сумму кадра IPv6, а опции `--tcp-*` попадают в него; `--badsum`
    у C ничего не делает (`main-conf.c:2758`).
  - Адрес источника берётся по маршруту к цели: ULA (`fc00::/7`) и `2001:db8::/32` допустимы, link-local только для цели
    link-local. C берёт первый адрес интерфейса со старшим байтом ниже `0xFC` вне `2001:db8::/32`, то есть никогда не ULA
    и не link-local (`rawsock-getip6.c:68–71`), поэтому на стенде с ULA C требует `--adapter-ip`.
  - MAC следующего хопа IPv6 разрешается Neighbor Solicitation (RFC 4861) к хопу маршрута ОС, а для единственной
    on-link цели к самой цели; печатается `[+] router-mac-ipv6 = MAC (ndp: N requests, M ms)` (до 10 запросов с шагом
    1 с, как ARP), Ctrl-C прерывает. C ищет «какой-нибудь маршрутизатор» Router Solicitation на `ff02::2` и ждёт Router
    Advertisement (`stack-ndpv6.c:312–487`, RS `:386–388`, `main-initadapter.c:243`), это не обязательно хоп маршрута.
    Строки `[+]`: `source-ip = [адрес] (detected|given)`, `router-ip = [адрес] (почему)`; у C `source-ip = [адрес]` без
    суффикса (`main-initadapter.c:229`) и строки `router-ip` для IPv6 нет.
  - `--router-ipv6` как в C синоним `--router-mac-ipv6` и принимает MAC, не адрес (`main-conf.c:2614`). `--router-ip`
    принимает и адрес IPv6 (расширение: у C только IPv4, `main-conf.c:2626–2639`, ошибка `bad source IPv4 address`),
    `--adapter-ip` принимает адрес IPv6 как у C. Тексты ошибок обеих опций свои, не C, и называют оба семейства (`--router-ip`: `expected one IPv4 or IPv6 address`; `--adapter-ip`: `expected an IPv4 address or a range A-B of a power-of-two width, or an IPv6 address`). Опция принимает
    одно значение на флаг (`--adapter-ip A --adapter-ip B` — ошибка clap `cannot be used multiple times`; второе
    семейство задают `--adapter-ip[0]` или файлом конфигурации); C принимает повторы (проверено `--echo`).
  - Каждое семейство идёт по своему маршруту (IPv6 по таблице маршрутов IPv6). C берёт интерфейс маршрута IPv4 по
    умолчанию для обоих семейств (`main-initadapter.c:44–57`) и адрес IPv6 этого же интерфейса (`:212–219`). Смешанный
    скан, семейства которого идут через разные интерфейсы, отказывает (`IPv4 and IPv6 targets are routed via different
    interfaces`, код 1): режима одного интерфейса как у C нет.
  - Выбор адреса источника IPv6 на macOS не смотрит на состояние DAD: `SIOCGIFAFLAG_IN6` не читается, поэтому
    tentative и duplicate (DAD failed) адреса не отсеиваются, а deprecated не уходят в конец списка. Linux
    (`IFA_F_TENTATIVE`, `IFA_F_DADFAILED`) и Windows (`IpDadStateTentative`, `IpDadStateDuplicate`) отсеивают tentative и
    duplicate и ставят deprecated последними. Живой прогон на macOS не снимался (NOT RUN); если автоопределение взяло
    такой адрес, источник задают явно, `--adapter-ip`.
  - `--router-mac-ipv6`, равный MAC самого адаптера, отказывает при построении плана, до первого кадра (`the IPv6 next-hop MAC equals the adapter
    source MAC`; проверка в плане живого скана, офлайн её не достать; покрыто тестом плана): собственные кадры нельзя было бы отличить от ответов. Для IPv4 то же делают адаптеры macOS и Windows;
    у IPv6 проверка стоит в плане и действует на всех ОС.
  - Возобновление (`--resume`) заданий с IPv6 поддержано: `paused.conf` несёт диапазоны IPv6 и, только если заданы,
    `adapter-ip`, `router-ip` и `router-mac-ipv6` в форме IPv6; остаток потока точный (тест). `paused.conf` чисто
    IPv4-задания не изменился ни на байт. Значения `router-mac-ipv4` и `router-mac-ipv6` в файле могут различаться (C тоже
    принимает); C не читает `paused.conf` с `router-ip` IPv6.
  - Цели и диапазоны (`rmasscan-core` `ranges6.rs`): перевёрнутый диапазон IPv6 (`::5-::2`) отказывает при разборе, C
    принимает запись и падает на пределе 63 бит (`requested is 128 bits`, проверено). Исключение, затрагивающее `::` или
    последний адрес, вычитается как множество; у C `range6list_remove_range` не возвращается (`massip-rangesv6.c:408`,
    проверено `-sL ::/126 --exclude ::/126`). Запись из девяти групп отказывает, C падает по segfault (проверено).
    Смешанная форма `1.2.3.4-abcd::` не перенесена (C разбирает её как `abcd::`, проверено `--echo`). Неразобранный
    хвост (`2001:db8::1x`) и любая ошибка цели фатальны (C печатает `bad IP address/range` и продолжает). `-6` принимается как флаг
    без действия (`main-conf.c:3323–3325`), но в позиции значения опции (`--exclude -6`) пропадает до разбора значения.
    Адрес IPv6 без скобок, начинающийся с буквы (`fd00::/64`), в позиционном аргументе принимается; C отказывает
    (`unknown command-line parameter`, `main-conf.c:3594`).
  - `-iL` / `--includefile` отказывает на строке IPv6 (`invalid IP address on line #N`), C её принимает; `--excludefile`
    и `--exclude` принимают IPv6.
  - Приём: `ttl` записи IPv6 это настоящий hop limit ответа (`px[offset_ip + 7]`). C его не заполняет: `ip_ttl` ставится
    только для IPv4 (`proto-preprocess.c:127`), а `main.c:1085` отдаёт значение из прошлой итерации (живьём в `-oJ` C
    32-битные числа вроде 320995840; `-oB` хранит младший байт). Заголовок Hop-by-Hop пропускается по RFC 8200
    (`(длина + 1) * 8`), C берёт `px[1] + 8` (`proto-preprocess.c:300–312`, верно только при длине 0). Fragment
    и Routing отбрасываются, как у C; IPv6-кадры UDP, ICMPv6 и SCTP C разбирает (`proto-preprocess.c:288–291`), а rmasscan,
    сканирующий только TCP, отбрасывает любой кадр не TCP. Кадр DLT_NULL несёт `AF_INET6` хоста
    (`templ-pkt.c:1159–1161`: 10 Linux, 30 macOS, 23 Windows), а приём принимает 24, 28 и 30 в любом порядке байт, как C
    (`proto-preprocess.c:515–531`); скан через туннель по-прежнему не поддержан.
  - NDP на приёме (ответ на Neighbor Solicitation во время скана): запрос проверяется по RFC 4861 §7.1 (hop limit 255,
    code 0, сумма, длина, опции корректны, цель не multicast) и должен быть адресован нам или нашему solicited-node
    multicast; C принимает любой адрес `ff02::/16` (`main.c:515–520`, `:832`) и не проверяет hop limit, code и сумму. Запрос от `::`
    (проверка дубликата адреса) остаётся без ответа, у C отвечает. NA несёт hop limit 255 и нулевые traffic class и flow
    label (C копирует их из запроса), `payload_length` всегда 32 (C копирует запрос целиком и длину не переписывает,
    `stack-ndpv6.c:145`, `:149`, `:156–161`); кадр NDP с заголовком расширения отбрасывается (C проходит цепочку
    расширений); ошибка передачи NA игнорируется. Ответ C
    выходит только по случайности: `parsed->opcode` задаёт только разбор ARP, `parse_icmpv6` его не трогает, а
    `stack-ndpv6.c:112` и `main.c:833, :845` читают устаревшее значение. NA без опции 2 (Target Link-Layer Address)
    резолвером не используется.
  - `--iflist` об IPv6 ничего не печатает (свой формат, поле `ipv4=` у интерфейса). На Windows адаптер без привязки IPv4
    выбрать нельзя: список адаптеров строится по IPv4, адреса IPv6 читаются отдельным вызовом `AF_INET6`, как у C
    (`rawsock-getip6.c:114–119`). На macOS читается один маршрут IPv6 по умолчанию (`RTM_GET ::`): при включённом VPN,
    который держит его, маршрута к цели нет (`could not determine default interface`), обходятся `--interface` и
    `--router-mac-ipv6`. Несколько on-link целей IPv6 требуют шлюза IPv6 по умолчанию, иначе отказ `no IPv6 default
    gateway on interface … for several on-link targets` (`NoGateway6`), как для IPv4 без шлюза.
  - `--packet-trace` печатает кадр IPv6 строкой TCP-формата C: `SENT (0.0000) TCP  [src]:port > [dst]:port SYN`
    (формат равен живой трассе C: кадр IPv6 TCP C разбирает как `FOUND_TCP`, `proto-preprocess.c:288`, и печатает ту же строку, `main-ptrace.c:35–40, 92–99`; `FOUND_IPV6`, `:100–101`, это неразобранная нагрузка; эталона C нет, потому что трасса C в `--offline` пуста, `rawsock.c:292–293`).
  - `--readscan` читает записи IPv6 (типы 10 и 11); запись с `ip_proto` не 6, 17, 132 или 1 отказывает
    (`unsupported record protocol P`), тип 12 (ARP IPv6) читать нельзя (`unsupported record type 12`; писатель в C его
    умеет, `out-binary.c:121`, читатель C его не знает). Фильтр по цели IPv6 без диапазона IPv4 фильтрует: остаются
    записи внутри диапазонов IPv6, записи IPv4 в набор не входят. C в этом случае фильтр адресов не применяет и
    пропускает всё (`in-filter.c:10`, `in-binary.c:254`: условие `count_ipv4s != 0`); эталона C на это нет, поведение
    закреплено тестом. Фильтр IPv6, исключённый до пустоты, снимает фильтр по адресу, как это делает C для IPv4. `-p U:53`
    для записей IPv6 работает так же, как для IPv4 (блок «Протоколы IPv4», `in-filter.c:14–17`).
- Баннеры, подэтап 4a (спека `../docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md`, Р1–Р17, §9; справка
  `../docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md`; случаи и измерения UDP-парсеров в
  `tests/golden/udp-banners/README.md`). Ссылки на C это masscan `8e6b3b0`:
  - Только UDP. `--banners` или `--rawudp` вместе с портом TCP в скане (живом и `--offline`) отказывают с кодом 1 до
    первого кадра: TCP-баннерам нужен собственный стек TCP (`src/stack-tcp-core.c`), он придёт в подэтапе 4b. `-sL`,
    `--echo` и `--readscan` порты не проверяют. Скан UDP поверх IPv6 по-прежнему отказывает (R3 блока «IPv6»), поэтому
    баннеры UDP есть только у IPv4; путь баннера IPv6 (cookie `syn_cookie_ipv6`, hop limit как TTL) готов и закреплён
    тестом движка. Hello из `nmap-service-probes` (16 строк, `src/proto-banner1.c:327-489`) не переносятся и в 4b
    (Р3): на их портах rmasscan не будет слать hello, а C ответы на них всё равно не разбирает.
  - Сырой баннер это сама датаграмма. На 11211 и портах без парсера C читает `app_length` байт, начиная за концом
    датаграммы (`src/proto-udp.c:97-101, 108-112, 129`: `px` уже сдвинут на `app_offset`), то есть память буфера захвата
    (Р2). Длина та же, что у C.
  - Дедупликация UDP: у C каждая датаграмма это запись `open udp` и её баннеры (`src/main.c:909-916`,
    `src/proto-udp.c:63-73`), дубль и повтор зонда тоже; у rmasscan ответ проходит `DedupCache` (блок «Протоколы IPv4»),
    и баннеры идут только за ответом, прошедшим дедуп: одна запись и один набор баннеров на ответ.
  - Время записи баннера равно времени записи статуса его ответа: у rmasscan это момент обработки пачки (Р9 этапа
    вывода), у C оба получают время захвата кадра (`secs`, `src/main.c:915`). TTL баннера тот же, что у записи;
    у ответа IPv6 это настоящий hop limit (у C `ip_ttl` для IPv6 не заполняется, справка C1.5).
  - Cookie: DNS (53) и NBNS (137) сверяют id с младшими 16 битами cookie, SNMP (161) request-id с 31 битом, ISAKMP (500)
    cookie инициатора; CoAP и memcached при несовпадении дописывают ` IP-MISMATCH` (справка B10), как C. У
    пользовательской нагрузки (`--nmap-payloads`, `--pcap-payloads`) мутатора cookie нет (`src/templ-payloads.c:619-680`),
    поэтому DNS, NBNS и SNMP по ней молчат, CoAP и memcached пишут ` IP-MISMATCH`, ISAKMP даёт сырой баннер: так же у C.
    Датаграмма DNS или NBNS короче 12 байт это несовпадение cookie, а ответ без нужной записи даёт сырой баннер (у C
    там неинициализированные `id` и `rr_offset[]`, `src/proto-dns.c:205-206, 419`, `src/proto-netbios.c:144`). Текст TXT и
    MAC NBSTAT читаются до конца датаграммы (C читает до конца кадра, `src/proto-dns.c:420-434`,
    `src/proto-netbios.c:145-166`, и хвост захвата за IP-пакетом, например FCS, попадает в текст).
  - Указатели сжатия DNS и NBNS адресуют сообщение DNS, у C кадр захвата (`src/proto-dns.c:69`), и проверка имени у C
    читает байты канального и IP-заголовков. Измерено: в Ethernet + IPv4 обычный ответ совпадает с C, а в Ethernet + IPv6
    и с тегом 802.1Q там, где rmasscan печатает `dns-ver` или `nbtstat` для ответа со сжатым именем ответа, C печатает
    только сырой баннер; для экзотических указателей (на байты id, цепочка из пяти, петля) наоборот: C печатает
    `dns-ver`, rmasscan сырой баннер. У канала без заголовка (raw IP) исход C зависит от адреса источника; Linux cooked
    capture и loopback не измерены. Списки случаев по каналам: `tests/golden/udp-banners/README.md`, раздел «What the
    goldens show».
  - ISAKMP: чтение ограничено датаграммой (C читает память захвата за ней, `src/proto-isakmp.c:49`, `:246`, и печатает из
    неё фантомные vendor id), текст обрезается ровно на 65 536 байтах и разбор на этом кончается (Р5; у C текст растёт
    квадратично от длины датаграммы, `src/proto-isakmp.c:48-50`). На четырёх видах ответа C не выходит из цикла
    никогда (нагрузка, предложение или преобразование нулевой длины, хвост атрибута в один байт,
    `src/proto-isakmp.c:68-70, 146, 191, 372`): поток приёма C встаёт, rmasscan делает шаг один раз и идёт дальше.
  - ZeroAccess: датаграмма длиннее 2048 байт у rmasscan не ZeroAccess (C считает CRC за буфером на стеке,
    `src/proto-zeroaccess.c:176, 208`, и печатает тот же сырой баннер); буфер баннера без `max_length`
    (`src/proto-zeroaccess.c:183-185`, у C зависание или запись за `banner[200]`) у rmasscan обычный баннер.
  - Ошибки памяти C, которые не переносятся (вывод от них не зависит): чтение за буфером в `dns_extract_name`
    (`src/proto-dns.c:164`, вызов `:318`, ответ DNS или NBNS без записей), байт тега за датаграммой в `asn1_integer`
    (`src/proto-snmp.c:151`), `px[length]` в разборе memcached (`src/proto-memcached.c:165`), до трёх байт за датаграммой в
    `zadecrypt` (`src/proto-zeroaccess.c:121-123`), знаковые сдвиги UBSan (`src/util-extract.c:58, 60`,
    `src/proto-zeroaccess.c:206`).
  - `assert(info->app_length < 2000)` (`src/proto-preprocess.c:174`) у C живой: в Makefile нет `-DNDEBUG`, и
    `preprocess_frame` с датаграммой от 2000 байт нагрузки завершает C по SIGABRT. В приёме скана такой кадр не доходит до
    разбора ни у C, ни у rmasscan (кадр длиннее 1514 байт отбрасывается, `src/main.c:799`), но C падает на
    `--pcap-payloads` с такой датаграммой в захвате (`src/templ-payloads.c:743`) и при поиске MAC роутера IPv6, если
    адаптер отдал такой кадр (`src/stack-ndpv6.c:471`, без проверки 1514). rmasscan не падает: `--pcap-payloads`
    принимает нагрузку до 2006 байт и отказывает на более длинной, NDP разбирает только NA, а парсеры баннеров берут
    датаграмму любой длины (тесты движка).
  - Р5: нагрузка каждой записи баннера не длиннее 65 536 байт; при этом вывод любого формата совпадает с C (текст режется
    на 8192, JSON на 65 536 экранированных символах, `-oB` молча выбрасывает записи от 16 370 байт, как C).
  - Р17: опции баннеров есть в файле конфигурации и в `--echo` в порядке C, но ошибки фатальны: неизвестное значение
    `--capture`/`--nocapture` печатает строку C (`FAIL: X: unknown capture type`, `src/main-conf.c:1159`, `:1174`) и
    завершает с кодом 1 (C продолжает разбор), нечисловой `--hello-timeout` это код 1 (у C 0). `--hello-timeout`
    принимается и ни на что не влияет, как у C. Имена этих опций на командной строке сравниваются по `EQUALS` C
    (регистр и `-`, `.`, `_` не важны: `--No-Banners`, `--raw_udp`, `--hello.timeout`); остальные опции rmasscan
    сверяет точно, со своими синонимами.
  - `--readscan` баннеров: фильтр `-p` у баннера сравнивает пару (протокол, порт) со сдвинутыми диапазонами, как у записи
    статуса (Р5 блока «Протоколы IPv4»: `-p U:53` оставляет баннер UDP 53, у C не остаётся ничего, `src/in-filter.c:14-17`),
    а баннер с протоколом без своего пространства портов (не 1, 6, 17, 132) под `-p` не проходит никогда; фильтр из
    одних диапазонов IPv6 фильтрует и баннеры (R14 блока «IPv6», у C не фильтрует ничего, `src/in-filter.c:10`). Тип 3
    с телом короче 12 байт это `[-] file corrupt` и код 1 (у C `buf_length - 12` переполняется и `output_report_banner`
    читает около 4 ГиБ, `src/in-binary.c:363`). С `--banner-types` запись типа 8 (ARP) пропускается молча, как прочие
    записи статуса, а C на ней печатает `[-] file corrupt: unknown type 8` и прекращает чтение (`src/in-binary.c:631-633`).
    Обрыв длины или тела записи, в том числе баннера, это `[-] file corrupt` и код 1, а C молча прекращает чтение
    (`break`), пишет подвал и выходит с кодом 0 (`src/in-binary.c:557-578`).
- `--adapter` на Windows принимает `\Device\NPF_{GUID}` или имя адаптера; числовых индексов нет. Wi-Fi
  (IfType 71) принимается как Ethernet (как C и Npcap `DLT_EN10MB`).
- Явный не-Ethernet `--adapter` отказывает (masscan проверяет тип только при автовыборе).
- Отказы обнаружения, которых у masscan нет (в форме C `[-] FAIL: …` и `[hint]`): цель это адрес самого хоста
  (`LocalTarget`, `is an address of this host`), первая и последняя цель идут разными маршрутами (`SplitRoutes`,
  `targets are routed differently`; оба и с `--adapter`, если не заданы `--router-ip`/`--router-mac`, тогда с
  подсказками маршрутизатора masscan вместо `--interface ethX`), среди целей
  нет unicast-адресов (`NoUnicastTargets`), MAC интерфейса скрыт ОС (`MacMasked`, `os-masked`), `--adapter` не
  совпадает с интерфейсом маршрута к целям (`RouteNotViaAdapter`, `route doesn't match interface` с подсказками
  маршрутизатора; masscan на macOS/BSD печатает `ERROR: ROUTE DOESN'T MATCH INTERFACE` и завершается,
  `rawsock-getroute.c:211–213`).
- Явный `--adapter-mac 02-00-00-00-00-00` (заполнитель скрытого MAC Darwin) или групповой MAC отказывает
  (`failed to detect MAC address`); masscan принимает любой ненулевой MAC.
- Туннели (VPN, `DLT_NULL`) и VLAN не поддержаны.
- ARP-таймаут 10 с: 10 запросов с шагом 1 с (masscan около 12 запросов за 11 с); ответ принимается строже C.
- Отказ ARP-таймаута печатает адрес, который разрешался, а для единственной on-link цели пишет
  `for next hop (target) IF: "IP"`; masscan всегда пишет `for router` и печатает заданный `--router-ip`, то есть
  `0.0.0.0`, если шлюз определён сам (`main-initadapter.c:195–196`).
- `--offline` с явными ненулевыми `--adapter-ip` и `--adapter-mac` и с `--source-port` не опрашивает ОС вовсе
  (masscan и в offline ищет интерфейс по умолчанию без `--interface`) и без `--adapter` печатает
  `[+] interface = none (offline)`. MAC шлюза в `--offline` всегда `66-55-44-33-22-11`, в том числе при
  `--router-mac`, и маршрутизатор не ищется (как C).
- Обнаружение, `--offline` и `--iflist` не требуют привилегий и ничего не открывают (masscan открывает адаптер до
  определения MAC и IP). Скрытый ОС MAC (macOS без root) и нулевой MAC не становятся source MAC: отказ с
  подсказкой `--source-mac`.
- `--router-ip 0.0.0.0` (и `router-ip = 0.0.0.0` в `paused.conf`) значит «не задан», как в C; так же нулевые
  `--adapter-ip`, `--adapter-mac` и `--router-mac` (адрес и MAC определяются, шлюз ищется ARP-ом).
- Любая другая опция masscan (например `--heartbleed`, `--hello` или `--http-user-agent`) - ошибка.
- Закрытый stdout (`| head`) завершает процесс сразу с кодом 0.
- `--adapter-ip` принимает один адрес или диапазон `A-B` шириной в степень двойки, как в C (приём проверяет весь диапазон).
- Грамматика `--excludefile` уже, чем у `massip_parse_file`: по одной записи на строку
  (IPv4 или IPv6, CIDR, диапазон), без остальных форм C.
- `-iL` / `--includefile` (и ключ `includefile` файла) разбирают файл как `massip_parse_file`: записи через пробел,
  табуляцию, `\r`, `\n` или запятую, комментарии `#`, `;`, `/`, `-` в начале записи, адрес, диапазон (в том числе
  юникодные тире) и CIDR. Уже C: строка IPv6 (`invalid IP address on line #N`; C принимает), пустой октет (`1..2.3`),
  завершающая точка, пустой префикс (`1.2.3.4/`) и перевёрнутый диапазон отказывают, а файл `-` (stdin) не читается.
- `-c` / `--conf` / `--config` и `--resume` применяются в порядке `argv`: ключ правее файла его переопределяет, левее
  переопределяется им. `/etc/masscan/masscan.conf` не читается, пропавший файл и неизвестный ключ фатальны, вложенность
  `conf = ...` глубже 16 это ошибка (в C бесконечная рекурсия).
- Индекс адаптера `--adapter[i]`, `--adapter-ip[i]`, ... допустим только в `0..=7` (в C `nic[8]` переполняет массив);
  `--offline` поддерживает один адаптер.
- `--pcap` пишет один файл на все адаптеры (в C каждый RX-поток открывает его сам), только входящие кадры на наш
  `adapter-ip` и порт источника, и только в живом скане: с `--offline`, `-sL`, `--iflist` и `--readscan` отказ с кодом 1.
- Пауза и возобновление с несколькими адаптерами: в `resume-index` пишется база самого медленного адаптера, поэтому
  адаптеры, ушедшие дальше, при возобновлении заново шлют зонды, уже отправленные за этой базой (без потерь, не более
  двух отправок на зонд; C ведёт себя так же, `main.c:1408-1414`; повторные ответы убирает дедупликация). Точное
  мультимножество гарантировано только для одного адаптера. Исчерпавшие поток адаптеры в минимум не входят.
- Осознанные отказы парсера там, где C молча принимает ввод: перевёрнутый диапазон,
  завершающая точка, пустой CIDR, пустой октет, мусор в списке портов.
- `-sL` с `--retries` > 0 в C может зависнуть (main-listscan.c:35,
  crypto-blackrock.c:268-276); `list_scan` и CLI это обнаруживают и завершаются ошибкой
  `ScanError::NonTerminating` до любого вывода, зациклиться может только сырой
  `list_scan_indices` с ручным shuffle-циклом. Передача от этого свободна.

## Проверка «без C в сборке»

Граф сборки не должен содержать C-тулчейн (`cc`, `cmake`, `bindgen`,
`pkg-config`, libpcap). Проверяют два механизма: интеграционный тест
`crates/rmasscan-core/tests/no_c_in_build.rs` (`cargo tree -e normal,build,dev`) и
`cargo deny`. Точные команды для CI:

```bash
cargo install --locked cargo-deny@0.20.2
cargo deny check bans licenses sources
cargo test -p rmasscan-core --test no_c_in_build   # граф --workspace: включает engine и sha2
```

## Лабораторная приёмка Linux (2B)

Crate `rmasscan-net` (единственный, где допущен `unsafe`) открывает AF_PACKET по явному
binding. Здесь проверяется сам адаптер (`wire_scan`), а не CLI; живой скан CLI с автоопределением
принимается на отдельных запечатанных стендах. Проверка идёт только в замкнутом стенде (две netns + veth, без uplink/bridge/NAT):

```bash
# на Linux-хосте со sudo -n, ip, ethtool, tcpdump (независимый свидетель захвата), GNU time (perf) и закреплённым C-oracle
cargo build --locked --release -p rmasscan-lab
cargo build --locked --release -p rmasscan-net --example wire_scan
scripts/wire-lab.sh --oracle /path/to/oracle/masscan --out OUT --suite rust \
  --rust-bin target/release/examples/wire_scan --fixtures tests/golden/wire
scripts/wire-lab.sh --oracle /path/to/oracle/masscan --out OUT-perf --suite perf \
  --rust-bin target/release/examples/wire_scan --reps 5
RMASSCAN_WIRE_RESULTS=OUT RMASSCAN_WIRE_PERF_RESULTS=OUT-perf \
  cargo test --locked -p rmasscan-net --test linux_wire -- --ignored
cargo test --locked -p rmasscan-lab   # comparator and suite regression cases (no CLI self-test)
```

Все активные лабораторные инструменты и проверки перенесены в Rust crate
`rmasscan-lab`; Python не требуется. [Команды и границы проверки](docs/rust-lab.md).

Живой паритет протоколов IPv4 идёт на том же стенде: `scripts/wire-lab.sh --suite protocols` (случаи `p01`–`p05`, UDP,
SCTP и ICMP Echo, ARP, смесь; пиры отвечают сокетами ответчика лаборатории и ядром netns пира), офлайн-вердикт
`rmasscan-lab protocols-verify --dir DIR`. Подробности, границы и названные отклонения: [раздел «Protocols suite»](docs/rust-lab.md).

Живой паритет IPv6 (TCP SYN, NDP, смешанный скан) идёт на том же стенде с IPv6 только на паре veth: `scripts/wire-lab.sh --suite ipv6`
(случаи `v01`–`v03`), офлайн-вердикт `rmasscan-lab ipv6-verify --dir DIR`; подробности: [раздел «IPv6 suite»](docs/rust-lab.md).

`examples/wire_scan.rs` это лабораторный harness (`ReadyPlan` + `Engine` + `open_explicit`,
`--pause-after N`, `--resume-checkpoint FILE`), а не CLI. Тесты `linux_wire.rs` с `--ignored`
без каталога результатов падают с «NOT RUN», пропуск никогда не PASS.

## Ограничения

Живой скан CLI передаёт кадры в реальную сеть и требует привилегий для открытия адаптера: сканировать только свои
адреса. Обычные `cargo test` и CI сеть не трогают: тесты CLI идут через fake-бэкенд (настоящий `OsBackend` есть
только в бинарнике вне `cfg(test)`), бинарник в тестах запускается только с `--iflist`, `--offline`, `-sL`,
`--echo` или `--help`. Живые прогоны автоопределения выполняются только на запечатанных лабораторных стендах вне
CI; raw-сокеты в лабораторных тестах `rmasscan-net` (нужны CAP_NET_RAW и замкнутый стенд) тоже вне CI. Скан
идёт по IPv4 (TCP SYN, UDP, ICMP Echo, SCTP INIT, ARP) и IPv6 (только TCP SYN), до 8 адаптеров с одним следующим хопом на адаптер и семейство; баннеры только UDP (подэтап 4a, TCP-баннеры в 4b), туннели и VLAN не поддержаны.

Живой скан из CLI поддержан и принят только на запечатанных лабораторных стендах (Linux netns и veth, Windows VM с Npcap
в режиме Admin-only, пара `feth` на Mac); на физических NIC он не проверялся (NOT RUN). Вживую не проверены шлюз маршрута
к цели за маршрутизатором (`router-ip … (route gateway)`: на стендах все цели on-link, ветка покрыта офлайн-тестами) и
маршрут к единственной цели на macOS (на одном Mac цель стенда это адрес самого хоста, проверены отказ и
переопределения); MAC под root на macOS доказан одним кейсом. Порт источника по умолчанию один, а не два, как у
masscan; полный вывод `--iflist` в evidence не хранится (только
строка стенда, число строк и sha256). Подробности: `../docs/experiments/2026-10-27-rmasscan-autodetect-acceptance.md`,
разделы 1 и 9.

Управление сканом принято на Linux (netns и veth) и в регрессиях на Linux и Windows VM; **macOS живое окно
этого этапа не запускалось (NOT RUN, нужен `sudo` пользователя)**, физические NIC не использовались (NOT RUN), живой
Ctrl-C на Windows не снимался (консольное событие по ssh не доставить; обработчик покрыт юнит-тестами). Второй адаптер
проверен вживую только на Linux (вторая пара veth); на Windows и macOS несколько адаптеров покрыты тестами с
fake-бэкендом. Тесты Studio этого этапа идут в CI PR.

Протоколы IPv4 (UDP, ICMP Echo, SCTP INIT, ARP, префиксы `-p`, `--top-ports`, файлы нагрузок) приняты на Linux (netns и
veth, окно `protocols`, случаи `p01`–`p05`, C-оракул masscan `8e6b3b0`); на Windows VM снята только регрессия
автоопределения, протоколы вживую на Windows не запускались. Пир SCTP в окне это ответчик лаборатории на линке, а не
стек ядра (в ядре стенда SCTP не загружен). Живое окно не задействовало отклонения от C: дедупликацию повторов, отбрасывание
Echo с кодом не 0 и неверных сумм, нулевую сумму UDP (на проводе стенда ни одного такого случая), эти пути покрыты
офлайн-тестами. NOT RUN: macOS живое окно (нужен `sudo` пользователя), физические NIC; Studio проверяется в CI PR.
Скан ARP работает только в своём сегменте и не сочетается с портами; VLAN и туннели не поддержаны.

IPv6 (TCP SYN поверх IPv6, NDP, смешанный скан IPv4 и IPv6, записи IPv6 в выводе и `--readscan`, автоопределение интерфейса,
источника и следующего хопа) принят живьём только на Linux в запечатанных netns (`--suite ipv6`, случаи `v01`–`v03`, C-оракул
masscan `8e6b3b0`). **Windows IPv6 не снимался (NOT RUN):** на lab-NIC гостя IPv6 выключен исправлением стенда (решение этапа),
обнаружение IPv6 на Windows (`GetBestRoute2`, адреса `AF_INET6`) покрыто тестами и CI, а окно Windows этого этапа это регрессия
автоопределения IPv4. **macOS не снимался (NOT RUN)**, в том числе цели link-local на macOS; физические NIC всех ОС не использовались
(NOT RUN). Тесты Studio этого этапа идут только в CI PR (`studio/` не менялся). Живой Linux-стенд не упражнял
ответ NA на NS пира (пир ни разу не спрашивал), нарушения RFC 4861 во входящих кадрах, заголовки расширения, возобновление
заданий IPv6, записи типов 10 и 11 с чужим `ip_proto` и цели link-local: это покрыто офлайн-тестами и сверкой с кодом C.

Баннеры UDP (подэтап 4a: `--banners`, `--rawudp`, записи баннеров во всех форматах и в `--readscan`) проверены офлайн:
эталонами C-парсеров (`tests/golden/udp-banners/`, 204 случая), эталонами `--readscan` (`tests/golden/formats/`) и
тестами движка и CLI на фиктивном адаптере. Живое окно `banners` на стенде (C-оракул и rmasscan против одних UDP-ответчиков)
это следующая задача подэтапа; до него живая приёмка баннеров NOT RUN. Баннеры UDP поверх IPv6 недоступны, пока скан UDP
поверх IPv6 отказывает (R3).

Маршрут по умолчанию читается не в любой форме. На Linux маршрут, заданный объектом nexthop (`RTA_NH_ID`) или
многопутевой (`RTA_MULTIPATH`), не читается: на таком хосте скан нескольких целей on-link получает отказ
`NoGateway`. На macOS читается только основной маршрут по умолчанию (`RTM_GET 0.0.0.0`): если его держит VPN
`utun`, скан LAN на `en0` получает `NoGateway` вместо шлюза `en0`. В обоих случаях шлюз задают явно, `--router-ip`.

## Статус

IPv6 (код `0ce2a9e8`, evidence `f05e93df`, 2026-11-12, ветка `feat/rmasscan-ipv6`, база `fdd18b37`): TCP SYN поверх IPv6,
`syn_cookie_ipv6`, NDP (Neighbor Solicitation резолвера и ответы на NS пира), смешанная индексация IPv4 и IPv6, записи типов 10 и
11 во всех форматах вывода и в `--readscan` (119 эталонов C: 94 прежних и 25 с IPv6), определение интерфейса, адреса источника и
следующего хопа IPv6 на Linux, macOS и Windows, `--router-mac-ipv6`, IPv6 в `--adapter-ip` и `--router-ip`, возобновление заданий
IPv6. Принятый код `0ce2a9e8` — коммит слияния `ffb8d6c1` ветки с `origin/main` `d2a6603f` (интеграция Studio, PR #54 и #57: наблюдение
маршрутов и адаптеров на трёх ОС, ограниченный обмен PF_ROUTE на macOS, карта доставки IPv4 у планов Studio) плюс коммит только с
тестом. На нём все шесть окон прогнаны заново (набор r3, `safety_trips` пуст): Linux `ipv6` PASS 4/4 (`v01`–`v03`), регрессии
протоколов Linux PASS 6/6, управления сканом Linux PASS 7/7, вывода Linux PASS 18/18, автоопределения Linux PASS 13/13 и Windows VM
PASS 10/10. Тесты на `0ce2a9e8`: Mac 2201/0, minipc 2084/0, гость 1973/0; офлайн-тесты Studio (`cargo xtask test`) на Mac
484/0. Правило подтверждения 1e9 в `validate` и проверка MAC следующего хопа IPv6 в `ReadyPlan::new_cli` в коде под окнами есть, но
ни одно окно их не упражняет. Прежний набор r2 на `e9eaebeb` (до правок итогового ревью и до слияния): evidence `f089b071`, те же
вердикты. Итоговое ревью ветки (правки до `0e0bd100`) и ревью слияния пройдены. GO (stands) условно: зелёный CI на точном HEAD и
Studio CI PR фиксирует контролёр при слиянии. Windows IPv6, macOS
живой и физические NIC: NOT RUN. Сырые данные r3: `../docs/experiments/2026-11-12-rmasscan-ipv6-postmerge-raw/`; отчёт:
`../docs/experiments/2026-11-08-rmasscan-ipv6-acceptance.md` (раздел 11 — r3).

Протоколы IPv4 (код `82f0483`, evidence `1ddb975`, 2026-11-11, ветка `feat/rmasscan-protocols-ipv4`; повтор r4 после
итогового ревью этапа): UDP со встроенными и внешними нагрузками, ICMP Echo, SCTP INIT, ARP-скан, префиксы
`T:`/`U:`/`S:`/`I:`/`O:` в `-p`, `-sU`/`-sS`/`-sZ`, `--top-ports`, `--udp-ports`, `--ping`, `--arp`, записи этих протоколов во
всех форматах вывода и в `--readscan` (94 эталона C). Живая приёмка: Linux `protocols` PASS 6/6 (`p01`–`p05`), регрессии управления сканом Linux PASS 7/7, вывода
Linux PASS 18/18, автоопределения Linux PASS 13/13 и Windows VM PASS 10/10; тесты Mac 1964/0 (сводка в
`verification/mac-test-ws-summary.txt`), minipc 1836/0 и гость 1731/0.
GO (stands) условно: зелёный CI на точном HEAD и итоговое ревью ветки фиксирует контролёр при слиянии. macOS живой и
физические NIC: NOT RUN. Отчёт: `../docs/experiments/2026-11-08-rmasscan-protocols-ipv4-acceptance.md`.

Управление сканом (код `8059eac`, evidence `6509a8c`, 2026-11-10, ветка `feat/rmasscan-scan-control`): `--shard`,
`--retries`, `--wait`, пауза первым Ctrl-C с `paused.conf`, `--resume`/`--resume-index`/`--resume-count`, `--infinite`,
`-c`/`-iL`, `--adapter[0..7]`, `--pcap`, `--ttl`, `--badsum`, `--tcp-*`. Живая приёмка: Linux `scan-control` PASS 7/7,
регрессия вывода Linux PASS 18/18, автоопределения Linux PASS 13/13 и Windows VM PASS 10/10; тесты minipc 1702/0 и
гость 1598/0; CI `rmasscan` и `language-guard` на `8059eac` зелёные. macOS живой и физические NIC: NOT RUN.
Отчёт: `../docs/experiments/2026-11-08-rmasscan-scan-control-acceptance.md`.

Форматы вывода masscan, `--readscan`, строка статуса и Ctrl-C (код `cd0ad38`, evidence `f63d23f`, 2026-11-06, ветка
`feat/rmasscan-output-formats`): офлайн-паритет с C `8e6b3b0` на 74 эталонах `--readscan` (байты равны после маски только
полей «часы в момент записи»); живая приёмка на Linux netns PASS 18/18 (записи и заголовок равны C-оракулу в `o01`–`o11`,
подвал оракула в живом скане отсутствует, потому что C не заканчивает скан на этом стенде; подвал rmasscan равен подвалу
своего формата из его записей; `--nostatus`, прерывание и открытие файла проверены без оракула), регрессия
автоопределения Linux PASS 13/13 и Windows VM PASS 10/10. macOS живой, живой Ctrl-C на Windows и физические NIC:
NOT RUN. GO (stands): итоговое ревью ветки APPROVED, CI зелёный на последнем коммите с кодом `15f3e00` (PR #50). Отчёт:
`../docs/experiments/2026-11-06-rmasscan-output-acceptance.md`.

Живой скан CLI с автоопределением интерфейса, адреса и MAC источника и следующего хопа (код `5682194`, evidence
`f85ec33`, 2026-11-04, ветка `feat/rmasscan-autodetect`) принят на трёх запечатанных стендах: Linux netns PASS 13/13
(паритет с C-оракулом по байтам ARP-запроса, порядку SYN и строкам `Discovered`), Windows VM PASS 10/10, Mac `feth`
PASS 8/8 и под root 3/3; `[+] finished … sent N` равен числу SYN на проводе, до скана уходит только 60-байтовый
ARP-запрос к напечатанному `router-ip`. GO (stands): итоговое ревью ветки APPROVED, CI зелёный на точном HEAD.
Физические NIC: NOT RUN. Отчёт: `../docs/experiments/2026-10-27-rmasscan-autodetect-acceptance.md`.

Состояние остальных слоёв на commit `b346d4d` (код; evidence `7aa5b12`; 2026-10-24, ветка `feat/rmasscan-stage2b-linux`);
полная таблица (capability / слой / реализовано / проверка / ограничение / следующий этап)
находится в §0.2 спеки Studio. Кратко: raw I/O: Linux AF_PACKET
(замкнутый стенд); Windows (Npcap) реализован и принят на виртуальной машине (физический NIC открыт); macOS (BPF) реализован, живая приёмка выполнена на паре `feth` (части A и C PASS, часть B с одним INVALID `linkloss`), физический NIC открыт, см. `../docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md`. Дедупликация живёт в engine
(ограниченный FIFO), не в core. VLAN не поддержан (`Unsupported`). ARP: кодек в core,
резолвер следующего хопа (`arp_resolve`) и обнаружение шлюза (`discover`) в `rmasscan-net` (с `5682194`). Парсер paused.conf есть, пользовательского импорта нет. Engine реализует
контроль достоверности приёма (`Rx::health`, `RxLoss`/`RxStatsUnavailable`/`RxError`,
`Outcome.rx_health`) и watchdog TX (`EngineOptions::tx_stall_timeout`, 10 с,
`TxStalled`); `Completed` означает завершение с доступной статистикой без kernel drops,
а не обнаружение всех открытых портов. Дальнейшие абзацы этого раздела описывают
моменты 2A и этапа 1 (исторически).

Этап 2A (офлайн, без сети): crate `crates/rmasscan-engine` с отменяемым runtime
(один TX и один RX поток, Pause/Stop, ограниченные очереди), разбором недоверенных
RX-кадров, checkpoint/resume и fake-адаптером в памяти. Тесты проверяют побайтный
resume, остановку в пределах 1 с и ограниченную память на пространстве /0 (см.
`../docs/experiments/2026-10-23-rmasscan-stage2a.md`). Настоящий сетевой I/O
(AF_PACKET, BPF, Npcap), golden pcap и привилегированный runner это этап 2B и
позже; статус CI смотреть для конкретного HEAD. BENCHMARKS.md по-прежнему
описывает только офлайн-генерацию, не скорость передачи.

Этап 1 закрыт. Критерии выхода выполнены: `-sL` и `--echo` побайтно совпадают с C,
self-тесты C отображены на Rust (`tests/selftest_parity.rs`), передача и SYN покрыты
тестами и дифференциалами с C, генерация offline около 0.96–0.99 от C на minipc
(см. BENCHMARKS.md), C в графе сборки нет.

Статус CI относится к конкретному commit и в этом файле не фиксируется; CI собирает и гоняет offline-тесты (в том числе на macOS), но не живой Windows/macOS raw I/O.

Первые задачи этапа 2:

- API сканирования: ранний выход (`ControlFlow`) и колбэк со структурой `Probe`, принимающий
  `&EffectiveConfig`; перенос шага source-port/cookie/frame из CLI в core.
  (Уже сделано в ветке: приватные поля `EffectiveConfig`, отказ от seed 0 в `validate`,
  усиленная защита «без C».)
- Контракт вызывающего для throttle: один `Throttler` на поток передачи, запускаемый с
  `max_rate/nic_count` после 1-секундного ожидания; одни и те же часы для `start` и
  `next_batch`; возврат 0 означает «вызвать снова»; `current_rate` публикуется через
  `AtomicU64`.
