# rmasscan: нативная Windows-база (VM)

Дата: 2026-10-24. Область: корректность сборки и тестов в Windows 11 VM (QEMU, виртуальный
NIC e1000e). Это не проверка физического NIC и не throughput; готовность Studio к релизу не
утверждается. Живых `--ignored` тестов на NAT не запускалось, пакеты в сеть не отправлялись.

## Закреплённое дерево

| Параметр | Значение |
| --- | --- |
| Commit | `31a729f` (ветка `feat/rmasscan-stage2b-windows`) |
| Локальный main | `43ebe35` (merge commit, не отправлен в origin); дерево идентично `31a729f` |
| Источник в VM | `git archive` tar дерева `31a729f`, sha256 `68b92e3e377005a8b09d5199e6b9dc1c7b4638fff450ca37cfc68bbb0eedabbd` |
| Каталог в VM | `C:\Users\lab\src\rmasscan-31a729f\rmasscan` |
| Ревью Linux-базы | remediation final review: APPROVED на `31a729f` |
| CI на точном HEAD | NOT RUN: push не разрешён. Условие плана «проверить CI exact HEAD перед кодом адаптера» остаётся ОТКРЫТЫМ |

## Гостевая ОС

Windows 11 Pro 10.0.26300. Baseline выполнен на сборке 26300.9457. Позднее перезапуск VM
(Task 2) применил отложенное обновление, сейчас 26300.9711; baseline предшествует обновлению.
Позже Task 2 добавил второй (лабораторный) NIC, см. [windows-vm-lab.md](../../rmasscan/docs/windows-vm-lab.md);
в baseline он не участвовал.

## Toolchain

| Компонент | Версия |
| --- | --- |
| rustc / cargo | 1.99.1 (58cf8f9c3 2026-10-13) / 1.99.1 |
| rustfmt / clippy | 1.10.0-stable / 0.1.99 |
| cargo-deny | 0.20.2 |
| MSVC | 14.44.35207 (VS Build Tools 17.14.37806.7) |
| Windows SDK | 10.0.26100.0 |
| pwsh / git / python | 7.6.8 / 2.56.0.windows.3 / 3.13.15 |

Установщики VS Build Tools и rustup запускались раньше, чем уточнился объём работ; оба завершились
без ошибок (VS exit 0, rustup «unchanged»). Хэши: `vs_BuildTools.exe` sha256
`2A6AA7D94E38D457A4EB3930FC60056ECAB06865B2EB925E5275B8473A017583`, `rustup-init.exe` sha256
`00F139DA614DCED87D3C3D4121C43EEBDAC3C1BF8A5EE86B9D80DFD71C8D70FD`.

## Npcap

| Параметр | Значение |
| --- | --- |
| Версия | 1.90 (libpcap 1.10.7) |
| Установщик | официальный `npcap-1.90.exe`, sha256 `682b57e1c05ef375931975c9d6ded40888f4bfdf9f4b11571e654f962f1199b6`, Authenticode Valid, Nmap Software LLC |
| Способ | обычный GUI-мастер (бесплатная сборка не имеет тихого режима; OEM-ограничение не обходилось); переустановка поверх предыдущей установки с AdminOnly=0 |
| Параметры | AdminOnly=1, WinPcapCompatible=0, Dot11Support=0, LoopbackSupport=1 (значение по умолчанию установщика; встроен NPF_Loopback, legacy loopback adapter не установлен) |
| Служба | `npcap` Running |
| `C:\Windows\System32\Npcap\wpcap.dll` | 1.10.7, sha256 `332F81CC1671A6D12AB4D20264A00EE16D12F6883745E05C92EE4030B3896A9F` |
| `C:\Windows\System32\Npcap\Packet.dll` | 1.90, sha256 `6F9116D9747DD356DB97F6DFAF02FE1B9B0859EA3214856F17CED84D790658C2` |
| Перечисление | elevated `pcap_findalldevs` rc 0, 5 устройств (4 NPF-адаптера + NPF_Loopback, среди них Intel 82574L) |

Перезагрузка для Npcap не потребовалась. Драйвер продуктом/ZIP не поставляется.

## Результаты проверок (exit codes)

Команды выполнялись `base.ps1` в `rmasscan/` на дереве `31a729f`; коды сведены в
[codes.json](2026-10-24-rmasscan-windows-baseline-raw/codes.json) и
[manifest.json](2026-10-24-rmasscan-windows-baseline-raw/manifest.json).

| Проверка | Команда | Exit | Результат | Лог |
| --- | --- | --- | --- | --- |
| fmt | `cargo fmt --all --check` | 0 | PASS | [fmt.log](2026-10-24-rmasscan-windows-baseline-raw/fmt.log) |
| clippy | `cargo clippy --locked --workspace --all-targets -- -D warnings` | 0 | PASS | [clippy.log](2026-10-24-rmasscan-windows-baseline-raw/clippy.log) |
| workspace test (первый запуск) | `cargo test --locked --workspace` | 101 | **FAIL** (перемежающийся) | [test.log](2026-10-24-rmasscan-windows-baseline-raw/test.log) |
| no-C guard | `cargo test --locked -p rmasscan-core --test no_c_in_build` | 0 | PASS | [no_c_guard.log](2026-10-24-rmasscan-windows-baseline-raw/no_c_guard.log) |
| verify-wire self-test | `python scripts/verify-wire.py --self-test` | 0 | PASS | [verify_wire_selftest.log](2026-10-24-rmasscan-windows-baseline-raw/verify_wire_selftest.log) |
| wire_suite self-test | `python scripts/wire_suite.py --self-test` | 0 | PASS | [wire_suite_selftest.log](2026-10-24-rmasscan-windows-baseline-raw/wire_suite_selftest.log) |
| wire_scan release build | `cargo build --locked --release -p rmasscan-net --example wire_scan` | 0 | PASS | [wire_scan_build.log](2026-10-24-rmasscan-windows-baseline-raw/wire_scan_build.log) |
| cargo deny | `cargo deny check bans licenses sources` | 0 | PASS | [deny.log](2026-10-24-rmasscan-windows-baseline-raw/deny.log) |
| CLI --echo | `cargo run --locked -q -p rmasscan-cli -- --echo 10.0.0.0/24 -p80 --seed 1` | 0 | PASS | [cli_echo.log](2026-10-24-rmasscan-windows-baseline-raw/cli_echo.log) |

### Падение workspace test (не PASS)

Первый запуск `cargo test --locked --workspace` завершился кодом 101: тест
`tx_stall::persistent_would_block_fails_with_tx_stalled_after_ten_seconds`
упал на `crates\rmasscan-engine\tests\tx_stall.rs:63` (`left: 0`, `right: 2`); 8 из 9 тестов
файла прошли. Дополнительно:

- три изолированных повторных запуска `tx_stall` прошли (9/9):
  [rerun1](2026-10-24-rmasscan-windows-baseline-raw/tx_stall_rerun1.log),
  [rerun2](2026-10-24-rmasscan-windows-baseline-raw/tx_stall_rerun2.log),
  [rerun3](2026-10-24-rmasscan-windows-baseline-raw/tx_stall_rerun3.log);
- полный `--no-fail-fast` запуск: 320 passed, 0 failed, 7 ignored, exit 0
  ([test_nofailfast.log](2026-10-24-rmasscan-windows-baseline-raw/test_nofailfast.log)).

Тест нестабилен (прошёл повторно), но первый прогон провален, поэтому он записан как FAIL, а
не PASS. Расследование причины ведётся отдельно (в этом документе не решено). Холодная сборка
плюс тесты заняли около 2 мин 46 с.

## Вне baseline

Дополнительный прогон, подписанный `head-a298196-extra`, в действительности выполнен на дереве
предшествующего amend коммита `f2b035b` (неверное дерево), поэтому недействителен и в evidence не
включён; из него не делается никаких выводов о `a298196`. Скрипты установки и проверки лежат в
`C:\Users\lab\masscan-lab` и `C:\Users\lab\base` на VM, не в коде продукта.

## Evidence

Каталог [2026-10-24-rmasscan-windows-baseline-raw/](2026-10-24-rmasscan-windows-baseline-raw/):
логи проверок, `manifest.json`, `codes.json`, `inventory.txt`, скрипты `base.ps1`, `np.ps1`,
`fd.ps1`, контрольные суммы в `MANIFEST.sha256`. Исходный tar (1.2 МБ) не копировался;
воспроизводится `git archive` дерева `31a729f`, хэш указан выше.

Связанные документы: [windows-vm-access.md](2026-10-24-windows-vm-access.md),
[windows-vm-inventory.json](2026-10-24-windows-vm-inventory.json).
