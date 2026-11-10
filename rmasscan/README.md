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
cargo run -p rmasscan-cli -- -sL 10.0.0.0/30 -p80,443 --seed 1
cargo run -p rmasscan-cli -- --echo 10.0.0.0/24 -p80 --seed 1
cargo run -p rmasscan-cli -- --offline --packet-trace 10.0.0.0/30 -p80 --seed 1 \
  --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --source-port 40000-40003
```

Без флага операции rmasscan сканирует (IPv4, TCP SYN). Порядок: значения по умолчанию (seed, порт источника) →
проверка конфигурации → обнаружение (только чтение таблицы маршрутов и интерфейсов, без привилегий) → строки `[+]` →
ARP к следующему хопу (если не задан `--router-mac`) → открытие адаптера → скан. Привилегии нужны только для
открытия адаптера: Linux root или `CAP_NET_RAW`, macOS root или доступ к `/dev/bpf*`, Windows Administrator и
Npcap. В stderr идут строки `[+] interface`, `source-mac`, `source-ip`, `router-ip`, `router-mac`, `seed`,
`source-port` и `[+] finished: <итог>, sent N, replies N, open N`; в stdout строки
`Discovered open port N/tcp on IP` (побайтно как masscan). Отказ обнаружения или ARP печатается в форме C
(`[-] FAIL: …` и строки `[hint]`), код выхода 1; итог `Completed`/`Stopped` даёт 0, любой другой 1.
`-sL` и `--echo` побайтно совпадают с golden-фикстурами C.

Вывод. Форматы `-oL` (list), `-oJ` (json), `-oD` (ndjson), `-oG` (grepable), `-oX` (xml), `-oB` (binary), `-oH`
(hostonly), `-oU` (unicornscan) и `--output-format none` для записей статуса TCP-порта побайтно равны masscan `8e6b3b0`
(кроме полей, которые C берёт из часов в момент записи; 74 эталона C в `tests/golden/formats/`). Опции:
`--output-format`, `--output-filename`/`--output-file`, `--append-output`/`--output-append`, `--output-flush`,
`--open`/`--output-show-open`, `--show`, `--noshow`, `--interactive`/`--nointeractive`, `--stylesheet`, `--webxml`,
`--no-stylesheet`, `--status`/`--nostatus`, `--ndjson-status`.
С `-o…` stdout молчит (кроме `--interactive`), иначе идут строки `Discovered …`. `--readscan FILE…` читает файлы `-oB`
(записи статуса TCP) и пишет их теми же форматами; цели и порты, заданные до него, фильтруют записи. На stderr
скан печатает строку статуса masscan (`rate`, `done`, `found`) и стирает её 77 пробелами перед `[+] finished`.
С `--nostatus` строки статуса нет, а после скана в stdout идёт `N milliseconds elapsed`, кроме случая, когда stdout
это файл вывода (`-o… -`): C закрывает его вместе с файлом, и в stdout остаётся только формат. Ctrl-C: первое нажатие
ставит скан на паузу (абзац «Управление сканом» ниже), второе выходит с кодом 1.

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
  - `-oR` (redis), `certs` и ротация (`--rotate`, `--rotate-dir`, `--rotate-offset`, `--rotate-size`) отказывают с
    сообщением и кодом 1 (Р1); баннеры не поддержаны, поэтому нет и их записей (`--banners` не входит в этап).
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
  - `--readscan` читает только записи статуса TCP (Р13), остальное — ошибка с кодом 1: баннеры, IPv6, ARP и
    устаревшие типы дают `<файл>: unsupported record type N`, запись статуса (тип 6 или 7) с протоколом не TCP —
    `<файл>: unsupported record protocol P`. Обрыв посреди записи — `[-] file corrupt` и код 1 (C молча
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
- Туннели (VPN, `DLT_NULL`), VLAN и IPv6 не поддержаны.
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
- Любая другая опция masscan (например `--banners`) - ошибка.
- Закрытый stdout (`| head`) завершает процесс сразу с кодом 0.
- `--adapter-ip` принимает один адрес или диапазон `A-B` шириной в степень двойки, как в C (приём проверяет весь диапазон).
- Грамматика `--excludefile` уже, чем у `massip_parse_file`: по одной записи на строку
  (IPv4, CIDR, диапазон), без остальных форм C.
- `-iL` / `--includefile` (и ключ `includefile` файла) разбирают файл как `massip_parse_file`: записи через пробел,
  табуляцию, `\r`, `\n` или запятую, комментарии `#`, `;`, `/`, `-` в начале записи, адрес, диапазон (в том числе
  юникодные тире) и CIDR. Уже C: IPv6, пустой октет (`1..2.3`), завершающая точка, пустой префикс (`1.2.3.4/`) и
  перевёрнутый диапазон отказывают, а файл `-` (stdin) не читается.
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

`examples/wire_scan.rs` это лабораторный harness (`ReadyPlan` + `Engine` + `open_explicit`,
`--pause-after N`, `--resume-checkpoint FILE`), а не CLI. Тесты `linux_wire.rs` с `--ignored`
без каталога результатов падают с «NOT RUN», пропуск никогда не PASS.

## Ограничения

Живой скан CLI передаёт кадры в реальную сеть и требует привилегий для открытия адаптера: сканировать только свои
адреса. Обычные `cargo test` и CI сеть не трогают: тесты CLI идут через fake-бэкенд (настоящий `OsBackend` есть
только в бинарнике вне `cfg(test)`), бинарник в тестах запускается только с `--iflist`, `--offline`, `-sL`,
`--echo` или `--help`. Живые прогоны автоопределения выполняются только на запечатанных лабораторных стендах вне
CI; raw-сокеты в лабораторных тестах `rmasscan-net` (нужны CAP_NET_RAW и замкнутый стенд) тоже вне CI. Скан
идёт по IPv4, TCP SYN, до 8 адаптеров с одним следующим хопом на адаптер; туннели, VLAN и IPv6 не поддержаны.

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

Маршрут по умолчанию читается не в любой форме. На Linux маршрут, заданный объектом nexthop (`RTA_NH_ID`) или
многопутевой (`RTA_MULTIPATH`), не читается: на таком хосте скан нескольких целей on-link получает отказ
`NoGateway`. На macOS читается только основной маршрут по умолчанию (`RTM_GET 0.0.0.0`): если его держит VPN
`utun`, скан LAN на `en0` получает `NoGateway` вместо шлюза `en0`. В обоих случаях шлюз задают явно, `--router-ip`.

## Статус

Управление сканом (код `11a2235`, evidence `28c956e`, 2026-11-10, ветка `feat/rmasscan-scan-control`): `--shard`,
`--retries`, `--wait`, пауза первым Ctrl-C с `paused.conf`, `--resume`/`--resume-index`/`--resume-count`, `--infinite`,
`-c`/`-iL`, `--adapter[0..7]`, `--pcap`, `--ttl`, `--badsum`, `--tcp-*`. Живая приёмка: Linux `scan-control` PASS 7/7,
регрессия вывода Linux PASS 18/18, автоопределения Linux PASS 13/13 и Windows VM PASS 10/10; тесты minipc 1702/0 и
гость 1598/0; CI `rmasscan` и `language-guard` на `11a2235` зелёные. macOS живой и физические NIC: NOT RUN.
Отчёт: `../docs/experiments/2026-11-08-rmasscan-scan-control-acceptance.md`.

Форматы вывода masscan, `--readscan`, строка статуса и Ctrl-C (код `2b0e92c`, evidence `86f384f`, 2026-11-06, ветка
`feat/rmasscan-output-formats`): офлайн-паритет с C `8e6b3b0` на 74 эталонах `--readscan` (байты равны после маски только
полей «часы в момент записи»); живая приёмка на Linux netns PASS 18/18 (записи и заголовок равны C-оракулу в `o01`–`o11`,
подвал оракула в живом скане отсутствует, потому что C не заканчивает скан на этом стенде; подвал rmasscan равен подвалу
своего формата из его записей; `--nostatus`, прерывание и открытие файла проверены без оракула), регрессия
автоопределения Linux PASS 13/13 и Windows VM PASS 10/10. macOS живой, живой Ctrl-C на Windows и физические NIC:
NOT RUN. GO (stands): итоговое ревью ветки APPROVED, CI зелёный на последнем коммите с кодом `9907de0` (PR #50). Отчёт:
`../docs/experiments/2026-11-06-rmasscan-output-acceptance.md`.

Живой скан CLI с автоопределением интерфейса, адреса и MAC источника и следующего хопа (код `6c87e94`, evidence
`00110f9`, 2026-11-04, ветка `feat/rmasscan-autodetect`) принят на трёх запечатанных стендах: Linux netns PASS 13/13
(паритет с C-оракулом по байтам ARP-запроса, порядку SYN и строкам `Discovered`), Windows VM PASS 10/10, Mac `feth`
PASS 8/8 и под root 3/3; `[+] finished … sent N` равен числу SYN на проводе, до скана уходит только 60-байтовый
ARP-запрос к напечатанному `router-ip`. GO (stands): итоговое ревью ветки APPROVED, CI зелёный на точном HEAD.
Физические NIC: NOT RUN. Отчёт: `../docs/experiments/2026-10-27-rmasscan-autodetect-acceptance.md`.

Состояние остальных слоёв на commit `27e3042` (код; evidence `8479ff2`; 2026-10-24, ветка `feat/rmasscan-stage2b-linux`);
полная таблица (capability / слой / реализовано / проверка / ограничение / следующий этап)
находится в §0.2 спеки Studio. Кратко: raw I/O: Linux AF_PACKET
(замкнутый стенд); Windows (Npcap) реализован и принят на виртуальной машине (физический NIC открыт); macOS (BPF) реализован, живая приёмка выполнена на паре `feth` (части A и C PASS, часть B с одним INVALID `linkloss`), физический NIC открыт, см. `../docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md`. Дедупликация живёт в engine
(ограниченный FIFO), не в core. VLAN не поддержан (`Unsupported`). ARP: кодек в core,
резолвер следующего хопа (`arp_resolve`) и обнаружение шлюза (`discover`) в `rmasscan-net` (с `6c87e94`). Парсер paused.conf есть, пользовательского импорта нет. Engine реализует
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
