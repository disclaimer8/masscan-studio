# rmasscan: следующий этап на Windows VM — Implementation Plan

> Update: пользователь потребовал Rust-only tooling. Python-инструменты из этого
> исторического плана заменяются crate `rmasscan-lab`; актуальная миграция:
> [Rust-only lab](2026-10-24-rust-only-lab.md). Числовые контракты приёмки сохраняются.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** получить Windows/Npcap-адаптер с доказанными TX/RX, RX health,
Stop и pause/resume на изолированном виртуальном Ethernet-стенде.

**Architecture:** существующее Rust-ядро и engine сохраняются; добавляется
Windows-реализация net. У VM остаётся управляющий NAT, второй NIC подключается
только к отдельному Linux-пиру. Сетевые байты проверяются независимым capture.

**Tech Stack:** Rust 1.99.1 MSVC x64, PowerShell 7, Npcap 1.90, QEMU 10.2.1,
Linux network namespaces/TAP, существующий Python/C-oracle harness.

**Spec:** [общая спека, §0.1](../specs/2026-10-23-cross-platform-qt-rust-design.md),
[порт](../specs/2026-10-23-masscan-rust-port-design.md),
[подробный план Windows](2026-10-24-rmasscan-stage2b-windows.md).
Этот документ задаёт фактический стенд и последовательность исполнения последнего;
он не заменяет его ABI/FFI-контракты и не открывает заново выбор UI.

**Статус:** составление плана разрешено. Подготовка VM/toolchain и проверки
существующего кода отдельно разрешены пользователем. Реализация Windows-адаптера,
создание нового сетевого стенда, push/merge и публикация этим планом не выполнялись.

## База и готовность

- Текущий локальный HEAD при составлении: `31a729f4a19e733457c88cc6d50030e70b7c899a`.
  RX integrity, TX stall, EINTR и outgoing-test уже исправлены; повторно не переносить.
- Linux evidence: commit кода `27e3042`, evidence `8479ff2`, functional 141/0/0,
  40/40 valid performance captures, воспроизведённый RX overflow → RxLoss.
  Это данные [отчёта](../../experiments/2026-10-23-rmasscan-stage2b-linux.md),
  не новый прогон при составлении плана. CI точного будущего base HEAD остаётся
  отдельной проверкой перед началом кода Windows.
- `ssh winvm` с Mac через `home-pc` работает по ключу. Windows 11 Pro build 26300,
  6 vCPU, 8 GiB RAM. Гость `lab` — администратор. Пароли в репозиторий не писать.
- PowerShell 7.6.8, Git 2.56.0, MSVC Build Tools 17.14.42, Python 3.13.15,
  Rust 1.99.1 + rustfmt/clippy установлены. Native offline-проверка запускается
  отдельно; завершение установки не считается PASS тестов.
- Npcap 1.90 installer скачан, Authenticode Valid / Nmap Software LLC.
  Скачивание не считается установкой драйвера. Статус установки перепроверить.
- Сейчас только QEMU NAT и `e1000e`, guest 10.0.2.15. Изолированного L2-свитча нет.
  [Инвентарь и доступ](../../experiments/2026-10-24-windows-vm-access.md).

## Global Constraints

- Один сканирующий NIC, IPv4/TCP, TX=1/RX=1, retries=0, shard=1/1, rounds=14.
  Два NIC в VM не означают поддержку multi-NIC в engine.
- `Rx::health(timeout) -> Result<RxHealth, IoError>` обязателен. Только
  подтверждённый Some(0) допускает Completed/Stopped/Paused; None и ошибки
  не превращаются в ноль. Drops → Failed без checkpoint; результаты сохраняются.
- Вызов I/O/health ≤50 мс, Stop ≤1 с. Pause прекращает TX ≤1 с, затем RX wait=3.
  Период health 250 мс плюс ограниченные вызовы, фактический зазор до ~350 мс.
- TX stall 10 с для непрерывного WouldBlockUnsent; throttle вне окна.
  Только Sent продвигает cursor; Uncertain не повторяется и запрещает checkpoint.
- Raw TX разрешён только на новом lab NIC к своему Linux-пиру. Управляющий
  NAT не используется для сканов. Никаких пакетов в домашнюю/публичную подсеть.
- Не менять firewall, дефолтные маршруты, DNS основной сети, NIC хоста и другие VM.
  Изолированный bridge ниже — отдельный тестовый switch без uplink/IP/NAT/forwarding.
- PowerShell-команды оформлять файлами .ps1 и запускать `pwsh -File` через SSH.
  Не передавать длинный вложенный `-Command`; секреты не включать в скрипты/логи.
- Npcap устанавливается явно только на лабораторную VM по отдельному разрешению
  пользователя «ставь что надо»; продукт/ZIP не скачивает и не поставляет драйвер.
- Это VM correctness, не физический NIC/throughput и не готовность Studio к релизу.

## Review Focus

1. Выбран NAT NIC вместо lab NIC: отказ до первого send — задачи 2/3.
2. Npcap сообщает недостоверный ноль или неизвестные drops: нельзя получить
   ложный Completed/Paused — задачи 3/4.
3. Неблокирующий RX ошибочно принимается за bounded TX: отдельные замеры send,
   health, close и Stop — задача 3.
4. Переподключение NIC меняет GUID/binding; старый checkpoint не продолжает
   изменённое задание — задачи 3/4.
5. Логи/pcap относятся к разным сборкам или capture потерял хвост: INVALID,
   повторный запуск, никакого PASS по запуску EXE — задачи 1/4/5.

## 1. Закрепить рабочую Windows-базу

**Files:** `docs/experiments/2026-10-24-windows-vm-access.md`,
`docs/experiments/2026-10-24-windows-vm-inventory.json`; создать
`docs/experiments/2026-10-24-rmasscan-windows-baseline.md` и каталог evidence.
Скрипты установки/проверки сначала находятся в `C:\Users\lab\masscan-lab`, не в коде продукта.

**Interfaces:** manifest с commit, source archive SHA256, OS build, toolchain,
версией/подписью драйвера, отдельными exit codes каждой проверки.

- [ ] Закончить native workspace tests, fmt, Clippy, no-C guard, comparator self-test,
  сборку wire_scan, cargo deny и безопасный CLI --echo на закреплённом дереве.
  Никаких `--ignored` live-тестов на NAT.
- [ ] Установить Npcap обычным мастером, включить Admin-only, не включать Wi-Fi
  monitor/legacy loopback/WinPcap compatibility без необходимости. Проверить
  службу, DLL paths/versions/hashes, режим прав и возможность перечисления адаптеров.
- [ ] После reboot, если он потребуется, повторить SSH/инвентарь. Перезагрузка
  только после завершения установщиков/проверок, без потери другой работы в VM.
- [ ] Зафиксировать Windows-кандидат base commit; до кода адаптера проверить CI
  exact HEAD и review Linux-базы. Push/merge не подразумеваются поручением на план.

## 2. Создать изолированный switch и Linux-пира

**Files:** создать `rmasscan/scripts/windows-vm-lab.py`,
`rmasscan/scripts/windows-vm-lab.ps1`, `rmasscan/docs/windows-vm-lab.md`,
`rmasscan/scripts/tests/test_windows_vm_lab.py`.

**Interfaces:** Linux-команды `plan`, `up`, `status`, `down` с обязательными
`--run-id` и `--manifest`; Windows `.ps1 -Manifest <file> -Action Inventory|Configure|Verify`.
Manifest содержит созданные имена, MAC, GUID lab NIC, IP/binding и ownership.
`plan` ничего не меняет, `down` удаляет только объекты своего run-id.

Предложенная топология:

```text
Mac SSH → home-pc → existing QEMU NAT NIC → Windows management
Windows second e1000e NIC → TAP → dedicated bridge → veth → Linux peer netns
                             no host IP, no uplink, no forwarding/NAT
```

- [ ] RED offline: занятое имя bridge/TAP/netns, чужой ownership, наличие
  физического uplink, неоднозначный NIC, повторный down, незавершённый up.
  Проверка не должна удалять или переиспользовать чужие объекты.
- [ ] Preflight: проверить инструменты/KVM/QMP, действующие интерфейсы/маршруты,
  доступные ресурсы и отсутствие конфликтов адресов. Предложение lab-сети:
  `198.18.0.0/30`, Windows `.1`, Linux `.2`, без gateway/DNS. При конфликте
  остановиться; не перенастраивать имеющуюся сеть.
- [ ] Создать принадлежащие запуску bridge/TAP/veth/netns без внешнего порта.
  Подключить второй e1000e через QMP hotplug с фиксированным уникальным MAC.
  Если hotplug не поддержан, не перезапускать VM автоматически: подготовить
  изменение run.sh и согласовать окно выключения.
- [ ] В Windows найти второй адаптер по MAC, сохранить GUID/NPF name и назначить
  только lab-IP. Проверить, что management NIC/default route не изменились.
- [ ] Проверить связь только с Linux `.2`, одновременно capture на peer и проверку
  нулевого тестового трафика на uplink. Ошибка topology check запрещает raw-run.
- [ ] GREEN: `python3 -m unittest discover -s rmasscan/scripts/tests` и
  up/status/down в выделенном стенде; повторный down безопасен, SSH остаётся жив.

## 3. Npcap feasibility и Windows-адаптер

**Files/interfaces:** задачи 1–3 [подробного Windows-плана](2026-10-24-rmasscan-stage2b-windows.md):
`rmasscan-net/src/windows/{mod,ffi,loader,adapter,tests}.rs`,
`tests/windows_io.rs`, platform dispatch в `src/lib.rs`.
`open_explicit`, AdapterPair, Tx/Rx/RxHealth — существующий API, не новый runtime.

- [ ] Выполнить loader/ABI/fake tests до live-send: trusted DLL loading,
  точные Windows struct layouts, два owned handles, lifetime DLL, без blanket Sync.
- [ ] Проверить pcap_stats именно на Npcap 1.90: значения/сброс/переполнение
  счётчиков и ошибка чтения. Неподдержанный показатель → None. Если честный
  health недоступен, STOP для Windows GO, а не ослабление контракта engine.
- [ ] На lab NIC доказать RX/health/send/Stop deadlines при тишине, потоке мусора,
  отключении lab-link и нагрузке. Nonblocking RX не доказывает bounded sendpacket.
  В случае зависающего send — отдельное решение о cancellable I/O; не оставлять
  worker, способный отправить пакет после объявленного Stop.
- [ ] Реализовать RX копирование до следующего pcap-вызова, truncation checks,
  фильтрацию собственного TX, честные counters; send error с неизвестным исходом
  → Uncertain. Не классифицировать WouldBlock по тексту ошибки драйвера.
- [ ] Запретить NAT NIC на уровне lab harness: только GUID+MAC+binding из
  валидированного manifest. Checkpoint mismatch отвергается до открытия скана.
- [ ] GREEN: fake tests, workspace tests на Windows/Linux/Mac; live smoke только
  выбранный peer. Это первый критерий GO адаптера, не приёмка всего этапа.

## 4. Wire-приёмка и тесты отказов

**Files:** существующий `examples/wire_scan.rs`, новые `tests/windows_wire.rs`,
`scripts/windows-wire-lab.ps1`; Linux capture/oracle scripts из подробного плана.

**Interfaces:** source/binary manifest, pcap+capture metadata, Outcome.rx_health,
общий verifier. C-oracle генерирует эталон для тех же MAC/IP/seed/ports, без
нормализации различий по заголовкам пакета.

- [ ] Шесть классов functional cases, по два повтора; отдельно полнота Open/Closed,
  source-port single/range, exclusions и rejection чужих ответов.
- [ ] Для 16 probe: Pause на 0/1/8/15, продолжение == continuous == C по SYN-байтам
  и порядку. Завершённое задание не возобновляется, attempt_id меняется.
- [ ] Stop при rate=1, пустом RX, нагрузке, drain, полной очереди; NIC disconnect,
  mismatch/corrupt checkpoint, Admin-only permissions. После исхода нет новых SYN.
- [ ] Воспроизвести RX overflow и проверить измеренное drops>0 → RxLoss без
  checkpoint. Unknown/error health проверять fake API; не подменять реальный
  overflow искусственно записанным счётчиком.
- [ ] Снять 100/1k/10k/100k pps × 5 повторов, CPU/RSS, call latency, capture
  completeness и RX loss. VM-скорость записывать как VM-скорость; ±20% performance
  gate не отменяется успешным correctness и может остаться OPEN до sendqueue.
- [ ] Каждый pcap хэшируется до cleanup; failed/invalid прогоны сохраняются.
  Отсутствующие результаты — NOT RUN, неполный capture — INVALID, никогда PASS.

## 5. Отчёт, review и следующий переход

**Files:** создать `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance.md`,
каталог сырых evidence; обновить readiness table и подробный Windows-план.

- [ ] Приложить точный commit, чистоту дерева, hashes, topology, версии DLL/драйвера,
  ошибки/лимиты и результат каждой проверки. Secret-free logs; source ZIP совпадает с EXE.
- [ ] Провести независимое review FFI/ownership, health/stop/checkpoint и самого
  harness. Зелёный CI относится к точному review HEAD. Merge — отдельное решение.
- [ ] Явно отделить GO Windows VM correctness от physical NIC, throughput,
  macOS BPF, runner/IPC, UI и distribution. Не заменять физическую приёмку VM.

Далее: отдельный план macOS BPF → discovery/ARP/network identity → runner/IPC
и durable checkpoint → реальный Scan в Slint. Изменение порядка или продуктового
объёма согласовывается отдельно; UI и внешние Nmap-функции этим этапом не переписываются.

Самопроверка: базовые интерфейсы взяты из текущего кода, уже исправленные проблемы
не повторены; Review Focus 1→2/3, 2→3/4, 3→3, 4→3/4, 5→1/4/5.
Toolchain/install, VM correctness и product release имеют разные критерии успеха.
