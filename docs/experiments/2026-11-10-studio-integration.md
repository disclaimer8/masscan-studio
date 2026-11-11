# Studio: интеграция современного движка и обычного сетевого профиля

Рабочая ветка: `integration/studio-current-engine` в `masscan-studio-app`.
Исходная незавершённая GUI-работа сохранена коммитом `5f66355`.
Коммит `9f89f54` объединяет её с `feat/rmasscan-scan-control` на `11a2235`.
Рабочая копия и ветка Клода не изменялись; push и merge в main не выполнялись.
Финальный код Studio: `433f3d4b334d672c24533ed3b872d0d3636df005`.
Появившиеся во время работы коммиты Клода `28c956e` и `67c5d48` обновляют
документацию/доказательства scan-control. Diff исходников `rmasscan/crates`,
Cargo manifests/lock и Studio относительно `11a2235` пуст; нового кода движка
для повторной интеграции в этих двух коммитах нет.

## Совместимость движка

Разрешены 12 конфликтов: в отличие от проверки одного main, scan-control затронул
также построение probe. Сохранены новые CLI-возможности, исправления маршрутов
macOS/Windows, отмена ARP и необходимые Studio bounded observations,
per-destination MAC и checkpoint identity. Общие алгоритмы остаются в rmasscan;
второй копии движка или парсинга stdout в GUI нет.

- Core/engine/net: 678 passed, 0 failed, 22 ignored.
- Вся рабочая область rmasscan, все targets: 1902 passed, 0 failed, 23 ignored.
- Clippy rmasscan с `-D warnings`: успешно.
- Сохранены тесты точной последовательности probe, destination map и старых
  digest/checkpoint, плюс проверки нового scan-control.

## Обычный сетевой профиль

`MacPhysical` — отдельный профиль для macOS Wi-Fi/Ethernet. Его путь:
настройки → проверка маршрутов → авторизованный runner → ARP → durable report
→ TCP → история/экспорт. Поддержаны Pause/Resume, Stop и повторные попытки через
существующий engine/controller. Resume проверяет прежнюю сеть и MAC-карту;
потеря сети, helper или значимый разрыв часов прерывает скан.

Профиль не требует служебного лабораторного permit. Старые MacFeth/MacNetwork
сохраняют отдельные проверки и не переключаются в обычный режим после отказа.
IPC поднят до версии 4; нужен helper из того же пакета. Формат базы не менялся.

Автоматические проверки нового поведения:

- RED → GREEN: распознавание нового профиля, report/checkpoint и отказ смешивания
  с fixture job; read-only preflight без прав и packet handles; авторизация
  packet open и закрытие отменённого результата; ARP с правильным source;
  восстановление профиля в UI и запрет Start на неподдерживаемой ОС.
- Дополнительно: fixture отказ не переходит в physical; stdio runner без прав
  отказывает до packet preparation; SQLite report/checkpoint/profile/recovery
  проверяются на обоих сетевых профилях. Общие runner lifecycle тесты теперь
  упражняют MacPhysical, а отдельные fixture-тесты сохранены.

## Область native-проверки

Пользователь поручил самостоятельно найти подходящее собственное устройство.
По существующей SSH-конфигурации выбран домашний ПК `home-pc-lan`,
`192.168.1.148`; аутентифицированный SSH подтвердил интерфейс eno1 и listener
TCP/22. Лабораторная Windows VM занята проверками Клода и не используется.
Для native-проверки предназначена отдельная история Studio; результаты сборки
и результаты пользователя в обычном каталоге приложения не смешивались.

## Найденные и исправленные ошибки реального сценария

1. В `commit_scan_events` обычный физический report ошибочно попадал в проверку
   sealed fixture. Первый запуск остановился до TCP с `sealed fixture fixed job differs`.
   Теперь специальные проверки относятся только к MacNetwork; MacPhysical проходит
   обязательную проверку сохранённого report по исходному job перед ACK. Новый тест
   также подменяет report через SQLite trigger и подтверждает отсутствие ACK.
2. Форма настроек скрывала сообщения авторизации. Сообщение и Dismiss теперь
   присутствуют и в самой форме, с переносом длинного текста.
3. После перезапуска авторизация paused history зависела от новой пустой формы.
   Теперь она использует выбранный сохранённый job и проверяет его маршруты.
   Убран ложный запрос лабораторного manifest в этом сценарии.
4. Resume без авторизации переводил отображение в Interrupted при сохранённом
   checkpoint в базе. Теперь сохраняются Paused и кнопка Resume, выводится причина.

Регрессии 1, 3 и 4 сначала воспроизведены падающими тестами, затем исправлены.
Полный `cargo xtask test` на `d077b9d`: **442 passed, 0 failed, 2 ignored**,
Clippy `-D warnings` и fmt прошли. После последнего изменения controller на
`433f3d4` повторены затронутые app/UI тесты: **84 passed, 0 failed**, а также
Clippy всей Studio и fmt. Два ignored теста полного набора требуют внешних
системного resolver/Nmap; они не считаются пройденными.

## Фактически выполненная native-проверка

Действия выполнялись через обычные кнопки нативного окна Slint. TCP-захват
независимо выполнялся на интерфейсе eno1 домашнего ПК, с фильтром адреса Mac
`192.168.1.128` и TCP source-port 40000. Он не является захватом всего uplink
и не доказывает отсутствие любого другого трафика интерфейса.

| Сборка | Действие | Наблюдаемый результат |
|---|---|---|
| `d077b9d` | 22,65000, rate 10 | Completed, 2 результата: 22 Open, 65000 Closed; 2 SYN и ответы SYN/ACK + RST/ACK в pcap |
| `d077b9d` | 22,65000–65031, rate 1; Pause → Quit → reopen → Authorize → Resume | checkpoint на позиции 4/33; после продолжения 33 результата; ровно 33 SYN, каждый порт один раз |
| `d077b9d` | JSON через Save dialog | 33 уникальные строки и whole-scan coverage; backend MacPhysical, исходный job и MAC-маршрут сохранены |
| **`433f3d4`** | 22,65000–65007, seed 43, rate 1; Pause → Quit → reopen | Paused, 4 результата, checkpoint 278 bytes, next_index 4, report 116 bytes |
| **`433f3d4`** | Resume до авторизации | Остаётся Paused, checkpoint сохранён, понятное сообщение о необходимости авторизации |
| **`433f3d4`** | Authorize → Resume | Без ошибки fixture; Completed, 9 уникальных результатов; ровно 9 SYN на все попытки вместе |
| **`433f3d4`** | 33 порта, seed 44, rate 1 → Stop | Stopped, 3 сохранённых результата, 3 SYN; оставшиеся порты не отправлены |
| **`433f3d4`** | Новый Start после Stop: 22,65000, rate 10 | Completed, 2/2, 22 Open и 65000 Closed; ещё 2 SYN |
| **`433f3d4`** | JSON через Save dialog | `final-native.json`, 2 строки с правильными open/closed и исходным job/coverage |

В финальном pcap ровно **14 SYN = 9 + 3 + 2**. Первый Resume не повторяет четыре
ранее отправленных порта. Счётчики sent/received в нижней строке относятся к
текущей попытке; после Resume они могут быть меньше общего числа сохранённых строк.
История сохраняет отдельные Completed/Stopped сканы и первую неудачную проверку;
неудачная проверка не переименована в успешную.

Для авторизации использована существующая разрешённая development work session
(host PID 49278): штатный `work-session stage` зарегистрировал точные подписанные
GUI/helper hashes, затем selected tooling возвращён на xtask. Host не заменялся,
приложение работало от обычного пользователя, root выполнял только helper.
Свежий системный диалог авторизации/чистая установка этой сборки не проверялись.

## Готовый пакет и сохранённые доказательства

Финальный пакет: `studio/dist/build-1794310418289/Masscan Studio.app`.
Manifest: `studio/dist/build-1794310418289/manifest.json`.
macOS/aarch64, debug; source `433f3d4`, **dirty=false** при упаковке.
`codesign --verify --deep --strict` прошёл; GUI/runner используют системные dylib.

| Файл | SHA-256 |
|---|---|
| studio-ui | `664dc792118bf9e62fd45378453816bd1269dcd9b5e6efc400639f6cb9ac67c0` |
| studio-runner | `253771f1819eb29a8baa504e21dcd23aab2e2918b632b3413a867a330aaa3f9e` |
| studio-launcher | `48d981b11853d78ac49070cf2bdcb70da0b56e62568a46d7a3d53890189ebc28` |
| studio-inspect | `ab0d9de85d8622a04b6f61a872f90037be59481c0243643caad48c46d34a351f` |

Постоянный каталог: `/Users/owner/masscan-studio-evidence/2026-11-10-physical/`.
Он содержит `final-native.pcap`, `initial-native.pcap`, расшифровки tcpdump,
нативные JSON-экспорты, `history-snapshot.sqlite3`, manifests, логи тестов и
`evidence-summary.json` с идентификаторами сканов. Capture остановлен после теста.
Все проверки использовали отдельный `STUDIO_DATA_DIR`; обычная история не менялась.

## Что ещё требуется для выпуска

- **P1 — платформы:** реальный Studio scan на Linux/Windows пока закрыт; успешные
  CLI-проверки Клода не заменяют native GUI/privilege/packaging acceptance Studio.
- **P1 — широкая сеть:** текущий native проход подтверждает один direct target
  через en0. Multi-peer, routed targets, другие типы подключения, смена сети, sleep/wake
  и потеря интерфейса требуют отдельного физического прогона. Автоматические
  проверки отказов и отмены существуют, но физическими результатами не названы.
- **P1 — распространение:** release-сборка, Developer ID/notarization, чистая
  установка и системный authorization dialog на свежем окружении. Проверенный
  пакет — локальная ad-hoc подписанная debug-сборка.
- **P2 — возможности UI:** дополнительные режимы/параметры нового CLI доступны
  не полностью. Текущий GUI-профиль ограничен IPv4/TCP, одним интерфейсом,
  2048 candidates, 1024 effective addresses, 1048576 probes и 1000 packets/s.
  UDP/IPv6 и туннельные интерфейсы не объявляются поддержанными.
- **Перед merge:** CI и review именно integration-ветки. Локальные изменения
  закоммичены; push, PR и merge в main в этом проходе не выполнялись.

Логи текущего прохода: `/tmp/studio-engine-integration-*.log` и
`/tmp/studio-physical-*.log`; копии сохранены в постоянном каталоге выше.
