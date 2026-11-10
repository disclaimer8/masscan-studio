# Studio: интеграция современного движка и обычного сетевого профиля

Рабочая ветка: `integration/studio-current-engine` в `masscan-studio-app`.
Исходная незавершённая GUI-работа сохранена коммитом `5f66355`.
Коммит `9f89f54` объединяет её с `feat/rmasscan-scan-control` на `11a2235`.
Рабочая копия и ветка Клода не изменялись; push и merge в main не выполнялись.

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
и фактически выполненных действий фиксируются после их проверки.

Логи текущего прохода: `/tmp/studio-engine-integration-*.log` и
`/tmp/studio-physical-*.log`. Они временные; этот отчёт сохраняет выводы и версии.
