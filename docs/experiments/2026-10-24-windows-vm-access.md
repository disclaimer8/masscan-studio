# Windows VM: доступность стенда

Дата проверки: 2026-10-24. Пользователь разрешил использовать Windows VM на
домашнем ПК для работы над Masscan Studio/rmasscan.

## Подтверждено через хост

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
| Гостевая ОС | Windows 11 Pro, 64-bit; сейчас сборка 10.0.26300.9711 (baseline снят на 26300.9457, обновление применено рестартом VM в Task 2) |
| Второй NIC | `Ethernet 2` (изолированный лабораторный), добавлен позже в Task 2, см. [windows-vm-lab.md](../../rmasscan/docs/windows-vm-lab.md) |

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

## Текущее состояние (после Task 1)

- pwsh 7.6.8 установлен; скрипты запускаются как `pwsh -NoProfile -File x.ps1` по SSH.
  Windows PowerShell 5.1 остаётся встроенным.
- Toolchain: rustc/cargo 1.99.1, rustfmt 1.10.0, clippy 0.1.99, cargo-deny 0.20.2,
  MSVC 14.44.35207 (VS Build Tools 17.14.37806.7), Windows SDK 10.0.26100.0,
  git 2.56.0, python 3.13.15.
- Npcap 1.90 (официальный установщик, Authenticode Nmap Software LLC), установлен через
  обычный GUI-мастер: AdminOnly=1 (доступ только для администраторов), WinPcapCompatible=0,
  Dot11Support=0, LoopbackSupport=1 (значение по умолчанию; встроенный NPF_Loopback есть,
  legacy loopback adapter не установлен). Служба `npcap` запущена; из elevated-сессии
  `pcap_findalldevs` rc 0, 5 устройств.
- Нативный baseline на закреплённом дереве 31a729f записан в
  [rmasscan-windows-baseline.md](2026-10-24-rmasscan-windows-baseline.md).
- Свободно около 19 GiB на C: после toolchain.
- Пароль УЧЁТНОЙ ЗАПИСИ в документах не хранится; вход по ключу.

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
