# Windows VM: доступность стенда

Дата проверки: 2026-10-24. Пользователь разрешил использовать Windows VM на
домашнем ПК для работы над Masscan Studio/rmasscan.

## Подтверждено через хост (первая проверка Codex, до установки toolchain)

| Параметр | Значение |
| --- | --- |
| SSH хоста | существующий alias `home-pc`, пользователь `a1` |
| Хост | Linux, `a1-System-Product-Name`, LAN `192.168.1.148` |
| VM | QEMU `win11`, QMP status `running` |
| QEMU | 10.2.1 |
| Каталог | `/home/a1/winvm` |
| Ресурсы | 6 vCPU, 8192 MiB RAM, CPU host |
| Диск | `win11.qcow2` |
| Сеть | QEMU user-mode NAT, виртуальный NIC `e1000e` |
| SSH forwarding | только на хосте `127.0.0.1:2222` → guest TCP 22 |
| RDP forwarding | только на хосте `127.0.0.1:33890` → guest TCP 3389 |
| Пользователь гостя | `lab`, вход по ключу подтверждён; administrator=true |
| Alias с Mac | `winvm`, ProxyJump `home-pc`, порт 2222 |
| Гостевая ОС | Windows 11 Pro, 10.0.26300, 64-bit (на момент первой проверки; текущая сборка см. раздел ниже) |

QMP доступен через `/home/a1/winvm/qmp.sock`. На момент первой проверки использованы
только запросы состояния/версии. Позже (Task 2) VM перезапускалась и получила второй
NIC; управляющий NAT-интерфейс и forwarding не менялись.

## Гостевой доступ: подтверждён повторной проверкой

Первоначальный timeout SSH устранён настройкой гостя вне этой проверки.
`ssh -o BatchMode=yes winvm whoami` успешно вернул `w-\lab`.
Пароль из сообщения пользователя не понадобился и в документы не записывался.

Первоначальный инвентарь (до установки) снят скопированным `.ps1` через встроенный
Windows PowerShell 5.1: pwsh, Rust/Cargo, Git, VS Build Tools, Windows SDK и Npcap
отсутствовали. Исходные данные: [inventory JSON](2026-10-24-windows-vm-inventory.json)
(теперь обновлён до текущего состояния; начальный снимок помечен в поле `collected_utc_initial`).

## Повторный снимок после обновления (2026-10-24T18:15Z)

Источник: свежий read-only снимок в гостевой ОС по SSH (план: повторить SSH и inventory после
перезагрузки). Все значения этого раздела получены из него, если не указано иное.

- Сборка ОС: 10.0.26300.9711 (UBR 9711, 26H2; [log](2026-10-24-rmasscan-windows-baseline-raw/after-update-os-build.log)).
  Baseline Task 1 выполнен на 26300.9457; обновление применено при рестарте VM в Task 2.
- Инвентарь: [inventory JSON](2026-10-24-windows-vm-inventory.json) целиком получен из одного запуска
  `masscan-winvm-inventory.ps1` ([скрипт](2026-10-24-rmasscan-windows-baseline-raw/after-update-inventory.ps1),
  копия вывода [after-update-inventory.json](2026-10-24-rmasscan-windows-baseline-raw/after-update-inventory.json)).
  Первоначальный снимок (10:04Z, до установки) заменён; он показывал отсутствие toolchain и Npcap.
- Адаптеры: `Ethernet` (управляющий NAT, 10.0.2.15/24) и `Ethernet 2` (лабораторный NIC, добавлен
  позже в Task 2, 198.18.0.1/30; см. [windows-vm-lab.md](../../rmasscan/docs/windows-vm-lab.md)).
  Оба показаны как `Intel(R) 82574L Gigabit Network Connection` / `... #2`.
- pwsh 7.6.8 присутствует; скрипты запускаются как `pwsh -NoProfile -File x.ps1` по SSH.
- Npcap: служба `npcap` Running, AdminOnly=1; подробности, подписи DLL и драйвера, результаты
  `pcap_findalldevs` (elevated и не-elevated) — в [baseline](2026-10-24-rmasscan-windows-baseline.md).
- Свободно около 18.5 GiB на C: (19 927 683 072 байт).

Из более раннего снимка Task 1 (не перепроверялось сейчас): версии rustc/cargo/clippy/cargo-deny,
MSVC 14.44.35207, Windows SDK 10.0.26100.0, git, python (см. baseline). Пароль учётной записи в
документах не хранится; вход по ключу.

## Следующие проверки

1. Доступ, inventory, toolchain и Npcap готовы (см. выше). Live-тесты `--ignored` на NAT
   не запускались и не запускаются.
2. Проверить существующий offline rmasscan и имеющийся Slint preview в гостевой
   ОС; привязать результаты к точному commit/binary hash. Установка отсутствующих
   компонентов должна быть явной; Npcap не ставить молча.
3. Для Npcap wire-тестов сначала подготовить отдельно согласованную изолированную
   Ethernet-топологию с независимым capture. Текущий NAT не считать доказательством
   L2 byte parity и не использовать домашнюю сеть как испытательный полигон.
4. Результат VM подтверждает работу в Windows с виртуальным NIC. Он не заменяет
   проверку физического адаптера, аппаратного throughput и драйверных различий.

Этот стенд дополняет Windows CI. Разрешение использовать VM не означает
утверждение исправлений из плана ревью, merge или публикации новой сборки.
