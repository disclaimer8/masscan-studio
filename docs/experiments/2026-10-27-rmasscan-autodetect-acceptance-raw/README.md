# Живая приёмка автоопределения rmasscan: Linux, Windows VM, Mac feth

План: `docs/superpowers/plans/2026-10-27-rmasscan-autodetect.md`, задача 7. Все четыре каталога сняты на одном
коммите **C = `6c87e942ea0ae349a62bd3ce507a1620233c575f`** (2026-11-04), из `git archive` этого коммита, чистое
дерево, release, `CARGO_INCREMENTAL=0`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. Вердикты вынес офлайн
`autodetect-verify` (Windows — `windows-verify`, который отдаёт такой каталог `autodetect-verify` целиком). После
копии в репозиторий хэши каждого прогона проверены повторно, и `autodetect-verify` копии дал тот же вердикт.

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) |
| --- | --- | --- | --- | --- |
| `linux-r1` | minipc, netns `wl-scan`/`wl-peer`, veth, C-оракул masscan 8e6b3b0 | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 2026-11-04 08:08:00Z |
| `windows-r1` | home-pc, QEMU Windows 11 гость, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only | `w01`–`w08b` (+ манифест) | **PASS 10/10** | 08:13:39Z–08:49:58Z |
| `macos-r1` | Mac, пара `feth4201/4202` `m1`, пользовательский режим в окне гранта BPF | `m01`–`m07` (+ манифест) | **PASS 8/8** | 08:30:37Z–08:31:24Z |
| `macos-root-r1` | тот же стенд, `--root-case` под `sudo` | `m10`, `m11` (+ манифест) | **PASS 3/3** | сразу после `macos-r1` |

Регрессия прежнего пути на том же коммите: `scripts/wire-lab.sh --suite rust` (`wire_scan`), rc 0, **145 PASS**
(`verification/minipc-rust-regress-results.json`; план называл 141, набор вырос до 145 ещё 2026-10-25).

## Ворота

- Статус стенда до и после каждого прогона (`status-pre.json`/`status-post.json` на Windows и macOS,
  `isolation.json`/`isolation-post.json` на Linux) — true; верификатор судит оба.
- 0 кадров лаборатории на uplink Mac (`en0`) и на `eno1` home-pc во всех прогонах; кадров с MAC вне пары
  сканер/пир стенда нет ни в одном захвате пира или оракула.
- Linux: отмена стенда записана в `linux-r1/teardown.json` (`namespaces_left: 0`), её `lab_id` совпадает с
  `manifest.json`.
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.
- Privacy: `grep -ralwE` по именам хостов и учётных записей Mac, minipc, home-pc и гостя, `_tcp.local`,
  `_udp.local` — 0 совпадений в четырёх каталогах. Полного `--iflist` нет нигде, только `iflist.json`
  (`l12` — и у masscan, со строкой `veth-a` в его форме).
- Стенды сняты: netns minipc удалены скриптом, `n2` — `vm-lab down` (rc 0), Mac — действие F
  (`verification/macos-status-after-F.json`: rc 3, `bpf_access: denied`, `/dev/bpf*` 0600 root:wheel).

## Версии

macOS 27.2 (26B123), tcpdump 4.99.1 (Apple 161); minipc Linux 7.0.0-38-generic, tcpdump 4.99.6; home-pc Linux
7.3.0-10-generic, QEMU 10.2.1; гость Windows 10.0.26300.9818, Npcap в режиме Admin-only (`AdminOnly=1`
проверен в реестре; номер версии в этом окне не перечитывался, по baseline 2026-10-24 — 1.90).
`rmasscan.exe` собран на госте со статическим CRT и `/DEPENDENTLOADFLAG:0x800`
(`verification/guest-build-rmasscan-dumpbin.txt`: `0800 Dependent Load Flag`).

## verification/

Офлайн-прогоны на C (перед окнами): Mac `cargo test --locked --workspace --all-targets` с
`RMASSCAN_EXPECT_DEFAULT_ROUTE=1` и без VPN — 1553 passed, 0 failed; clippy `-D warnings`, fmt, language guard —
чисто; minipc — 1428 passed, 0 failed; гость (elevated-сессия, Npcap Admin-only, строгий флаг маршрута) — 1328
passed, 0 failed. `cargo xtask test` в `studio/` — 168 passed, 3 failed: три теста
`feth_acceptance` падают так же на чистом `origin/main` 85b08f7 (Studio эта ветка не меняет). Логи suite и
верификатора всех окон. Пути и имена хостов в логах заменены на `$HOME`, `$SCRATCH`, `<user>`, `<mac>`,
`<minipc>`, `<home-pc>`, `<guest>`; файлы каталогов evidence не редактировались.

## Что было до этих каталогов (не закоммичено)

Окна шли трижды; первые два раза нашли дефекты продукта, их исправления и сменили C.

1. **C = 9496cd7.** Linux — PASS 13/13 (и регрессия 145 PASS). Windows: первая попытка — NOT RUN на
   предварительной проверке, часы гостя ушли на 6,2 с вперёд (служба времени не стартовала после перезапуска
   VM; `w32tm /resync` → −0,7 с); вторая — w01–w05, w07, w08a, w08b PASS, **w06 NOT RUN**: Windows отдаёт
   широковещательный адрес /30 (198.18.0.3) маршрутом с флагом MIB Loopback, и rmasscan называл его «an address of
   this host». Исправлено в b7e397a (`fix(net): a Windows broadcast route is on-link, not an address of this host`).
2. **C = b7e397a.** macOS: m01–m04, m06, m07 PASS, **m05 NOT RUN**: собственный адрес Mac 198.18.0.2 (на
   `feth4202`) Darwin отдаёт маршрутом подсети без RTF_LOCAL, пока сам хост не послал на него пакет, и rmasscan не
   узнавал свой адрес. Исправлено в 6c87e94 (`fix(net): a macOS target that is an address of this host is local`).
   Root-кейс m10/m11 — PASS 3/3; его первая попытка сразу после `up` остановилась на воротах до первого прогона
   (вывод не сохранился).
3. **C = 6c87e94.** Первый прогон macOS писал `--out` в scratch-каталог, путь которого содержит имя учётной
   записи; оно попало в `capture.json` (`tcpdump_argv`, путь `-w` в `.work`). Privacy-скан это поймал, каталоги не
   копировались; окно повторено из нейтрального каталога (`/private/tmp/rmasscan-ad.*`) — это `macos-r1` и
   `macos-root-r1` здесь.

## Отклонения от плана

- Root-кейс macOS шёл отдельной строкой `sudo` после пользовательского режима (три запроса `sudo` за окно вместо
  двух): так m05 гарантированно идёт на свежем стенде, где маршрут к своему адресу ещё не закеширован.
- На время окна macOS пользователь выключал VPN: с маршрутом по умолчанию через `utun` строгий офлайн-тест
  маршрута не проходит, а захват uplink на `en0` не увидел бы кадр, ушедший в туннель.
- Действия пользователя: A (2026-11-03), B (подъём + грант, root-строка), F; B1/B2 (перезапуск VM, `vm-lab up/down
  n2`, `record-guest`) выполнял оператор через существующий `sudo -n` по решению пользователя.
