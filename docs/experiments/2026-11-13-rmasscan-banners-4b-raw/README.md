# Живая приёмка подэтапа 4b rmasscan (TCP-стек и текстовые протоколы): окно `banners` с TCP-кейсами на стенде Linux, регрессии IPv6, протоколов, управления сканом, вывода и автоопределения (Linux, Windows VM), TCP-кейс Windows VM, фаззинг TCP

План: `docs/superpowers/plans/2026-11-13-rmasscan-banners-4b.md`, задача 19. Спека: `docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md`
(Р1–Р17; изменения по итогам 4b — §11). Справка C: `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tcp.md` (A–F, E1, E2).
Отчёт: `docs/experiments/2026-11-13-rmasscan-banners-4b-acceptance.md`. Набор r1 — первый набор подэтапа; ни одна попытка не
замещена, ни один каталог не перезапускался.

Все каталоги сняты на одном коммите **C = `0d1bdbceab8f63babfad4656f019d77abcea38e9`** (2026-11-15). Хосты называются по ролям:
хост стенда Linux (netns `wl-scan`/`wl-peer`, C-оракул), хост VM (QEMU-гость Windows 11, стенд `n2`), гость Windows, Mac
(оркестратор окон Windows, офлайн-верификаторы, фаззер, `privacy-scan`).
- Хост стенда Linux и гость: полное дерево из `git archive C` (sha256 архива `bd515cf8…02a4` на Mac, хосте стенда, хосте VM и
  госте; гость затем `git init; git add -A`, 18 289 файлов); хост VM: `rmasscan/` из того же архива; Mac: чистая рабочая копия
  на C, оркестратор Windows — из отдельной чистой рабочей копии на C (`--repo .`, `git_dirty: false`). Release,
  `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)` везде.
- Хэши бинарников: `verification/binaries.sha256.txt`.

| Каталог | Стенд | Кейсы | Вердикт | Проверок | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | ---: | --- | --- |
| `linux-banners-r1` | хост стенда Linux, стенд IPv6, в netns пира `icmp_ratemask=0`, `tcp_max_tw_buckets=0`, постоянные соседи источников TCP-кейсов, ответчик сценариев UDP и TCP, пульс, C-оракул masscan 8e6b3b0 | `b01`, `b02`, `t01`–`t09` (+ манифест) | **INVALID**: 11 PASS, `t06_noreset` INVALID (документ C), FAIL 0, `safety_trips` [] | 1115 | 16:58:07Z–17:06:45Z | `bcd5015bb72f19debfee819d1d420076ae2cdcc1b9a6dddc1a4eb860465dd18d` |
| `linux-ipv6-r1` | тот же хост, `--suite ipv6` | `v01`–`v03` (+ манифест) | **PASS 4/4**, `safety_trips` [] | 316 | 17:07:14Z–17:09:24Z | `b654b3ef09b2a325db2eefe742344431f0b47d9f06536a93b5f9fbe36c58bae9` |
| `linux-protocols-r1` | тот же хост, `--suite protocols` | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 467 | 17:09:51Z–17:13:13Z | `e5d629690c5ca4838b35064665180a7b125501a34db91221bcf1d4e25aae0b14` |
| `linux-scan-control-r1` | тот же хост, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 359 | 17:13:56Z–17:16:25Z | `13f596b50a3029cf480acb718284da1b45300dacc049563276b1e019faf918f1` |
| `linux-output-r1` | тот же хост, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 759 | 17:16:42Z–17:21:57Z | `a244916204744940aa53a55819980b37ac4d1c6aec3e8a1a842271b683404564` |
| `linux-autodetect-r1` | тот же хост, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 470 | 17:22:22Z–17:23:57Z | `304edf29ac1d81abb18513a0aa0c75bc1655f824fc30f401affa1a83e0f8073a` |
| `windows-autodetect-r1` | хост VM, гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 334 | 17:16:40Z–17:48:55Z | `c3ddade1c9dc800758addbec07a7e5bd2aab4952a2b9eda255491be4067602b2` |
| `windows-banners-r1` | тот же стенд, `--plan banners`, эталон — `t01_tcp4` окна `linux-banners-r1` (`reference/`) | `wb01_banners` (+ манифест, эталон) | **PASS 3/3**, `safety_trips` [] | 52 | 17:49:24Z–17:55:03Z | `86008fc7027a04563732b72ad06aa90e563dfcdbe8ab6cbeffed348d6de9a131` |

Вердикты Linux вынес верификатор хоста стенда (`banners-verify`, `ipv6-verify`, `protocols-verify`, `scan-control-verify`,
`output-verify`, `autodetect-verify`), Windows — `windows-verify` на Mac (передаёт каталоги `autodetect-verify` и
`banners_stand::verify_dir`). Верификатор Mac на C дал те же `verdict.json` байт в байт для всех шести каталогов Linux, и все
восемь — на копии в репозитории (`verification/rederive-on-committed-copy.txt`).

## Окно `banners` (`linux-banners-r1`)

Таблица кейсов, argv, сценарии и правила — `rmasscan/crates/rmasscan-lab/src/banners_verify.rs` и раздел «Banners suite» /
«Окно 4b» `rmasscan/docs/rust-lab.md`. TCP-кейсы: `t01_tcp4` (IPv4, 20 сценариев на 11 портах, `-oB` и `-oL`), `t02_tcp6`
(то же по IPv6), `t03_teardown`, `t04_banners_noreset`, `t05_stateless_rst`, `t06_noreset`, `t07_resolve_arp`, `t08_resolve_ndp`,
`t09_quiet_timers` (только rmasscan, без пульса). На документ шаг rmasscan и шаг C с одним argv, у каждого свой `peer.pcap`
и перезапущенный ответчик. `t07`/`t08`: `<шаг>/neigh-flush.json` — команда стирания записи соседа пира перед шагом и её код.

- `t01`/`t02`: в каждом из четырёх документов 20 `open` и 26 баннеров, равных C поле в поле без времени; сегменты сканера всех
  44 соединений равны C; 8 hello в окне 1,0–3,5 с, 2 RST жизни в 8–12 с; кадры стека C без неверной суммы IPv4 (230 в `t01`).
- `t06_noreset` INVALID: документ C — 5 записей при 4 различных ответах его провода (повтор SYN-ACK `198.18.0.5:80`, дедуп C
  `src/main-dedup.c:279`, разбор — раздел 3.2 отчёта); все проверки шага rmasscan PASS.
- C закончил каждый TCP-шаг с подвалом (пульс), каждый UDP-шаг — принудительным выходом, как прежде.

## TCP-кейс Windows (`windows-banners-r1`)

`reference/` — копия шага `oracle-list` кейса `t01_tcp4` из `linux-banners-r1` с `verdict.json` окна и `source.json` (хэши
`argv.json`, `output.txt`, `peer.pcap`, вердикт кейса пересчитан при копировании). `runs/wb01_banners/` — прогон CLI с
`--banners` на госте: `output.txt` (`-oL`), `guest-firewall.json` (профили файрвола и категория lab-NIC, только чтение),
захваты `peer.pcap` и `eno1.pcap`, ворота и записи runner.

## Фаззинг (`fuzz-tcp-r1/`)

`rmasscan-lab fuzz tcp` (Р15; `rmasscan/crates/rmasscan-lab/src/fuzz.rs`, раздел «Fuzzing the TCP banner parsers and the
stack» `rmasscan/docs/rust-lab.md`), сборка C на Mac, 13 процессов параллельно под `nice -n 19`, по 3700 с на семейство:
17:07:12Z–18:08:52Z (`command.txt`, `start.txt`, `exits.txt`). Корпус: 226 эталонов `tcp-banners`, 19 потоков сценариев, 166
потоков сервера из 29 `peer.pcap` окна `linux-banners-r1`. Итог: 1 031 129 169 входов, 0 падений, 0 медленных, 0 несовпадений
нарезки; 12 семейств `clean: true`, код 0; `stack` — 3 нарушения инварианта (`fuzz-tcp-stack.json`, `findings[]` с полным
воспроизводителем: параметры таблицы, поток, все события), код 1. `repro/` — повтор первой находки той же командой с
`--count 21020920` (детерминизм потока входов по seed).

## Ворота

- Linux: у каждого кейса `isolation.json`/`isolation-post.json` (режим `ipv6` у `linux-banners-r1` и `linux-ipv6-r1`,
  `scan-control` со вторым линком у `linux-scan-control-r1`, `autodetect` у трёх других); `teardown.json`: `namespaces_left: 0`,
  `lab_id` совпадает с `manifest.json`; каждый захват `valid: true`; `wire-lab`: `own_pids=0 stray_processes=0 namespaces_left=0`
  во всех шести окнах.
- Windows: в каждом из 10 прогонов `raw_run_allowed: true` в `status-pre.json` и `status-post.json`; на `eno1` хоста VM 0 кадров
  (каждый `eno1.pcap` — 24 байта); каждый захват `valid: true`; preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected:
  route to 198.18.0.2)`; часы гостя относительно хоста VM +0,47 с (неопределённость 3,6 с); `deploy/deploy-manifest.json` для C
  (lab хоста VM `0bdec3e4…`); оркестратор `c37ea06c…`, `build_commit`/`git_commit` = C, `git_dirty: false`; `exe.sha256` и
  `exe_sha256` каждого `guest-runner.json` = `rmasscan.exe` гостя `af6486c3…`. Перед наборами `vm-lab status`: `state: up`,
  `attached`, `host_ok` (`verification/vm-host-n2-status-before-suite.txt`); после `vm-lab down` (17:55:49Z, код 0) все четыре
  объекта MISSING, `lab.env` удалён (`verification/vm-host-n2-status-after-down.txt`).
- Стенд гостя (mDNS, LLMNR, DO выключены; IPv6 и NetBIOS выключены на lab-NIC; снимок применения —
  `docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/verification/guest-stand-applied.txt`) только читался:
  `verification/guest-stand-reading1.txt` (до `vm-lab up`) и `guest-stand-reading2.txt` (после перезапуска VM), каждая строка
  `reg` и `nic` обоих чтений равна снимку. Часы после перезапуска: `verification/guest-time-after-restart.txt`.

## verification/

- `binaries.sha256.txt`, `hosts-versions.txt`; Mac: `mac-gate-exits.txt`, `mac-test-ws-summary.txt` (2754 passed, 0 failed, 23
  ignored, 59 строк; полный лог в репозиторий не кладётся: тесты печатают временный каталог пользователя macOS и пути фикстур),
  `mac-clippy.log`, `mac-fmt.log`, `mac-language-guard.log`, `mac-studio-check.log`, `mac-build-lab.log`.
- Хост стенда Linux: `linux-stand-build.log`, `linux-stand-build-start.txt`, `linux-*-r1-window.log` (каталог, `SigIgn`, хэши
  бинарников, время, вывод `wire-lab.sh`, вердикт и его sha256), `linux-stand-test-ws.log`, `linux-stand-clippy.log`,
  `linux-stand-gate-exits.txt` (2633 passed, 1 failed, 14 ignored; clippy 0), `linux-stand-rerun-held-scenario.txt` (три
  повтора упавшего теста), `readscan-cross-check.txt` и `readscan/` (C и rmasscan `--readscan` каждого `-oB` окна в `-oL`,
  `-oJ`, `-oX`, `-oG`: `<кейс>.<binary — файл rmasscan | oracle-binary — файл C>.<c | rm — читатель>.<list.txt | json |
  xml.txt | grepable.txt>`, `*.list.notime.txt` — записи без времени, отсортированные; `.stdout`/`.stderr` читателей).
- Гость: `guest/guest-exits.txt`, `guest/guest-build-rmasscan.log`, `guest/guest-dumpbin-*.txt`, `guest/guest-test-ws.log`
  (2521 passed, 2 failed, 35 ignored), `guest/guest-clippy.log` (0), `guest/guest-rerun-two-failures.txt`.
- Хост VM и окна Windows: `vm-host-build.txt`, `vm-host-build.log`, `vm-host-n2-status-*.txt`, `windows-*-r1-suite.log`,
  `windows-*-r1-verify.log`.
- `privacy-scan.txt`, `rederive-on-committed-copy.txt`.

Пути в журналах: `$R` — каталог экспорта на хосте стенда, `$H` — временный каталог хоста VM, `$HOME` — домашний каталог хоста,
`$MACOUT` — нейтральный каталог набора на Mac, `$ORCH` — чистая рабочая копия оркестратора, `$REPO` — рабочая копия ветки,
`$TARGET` — каталог сборки Mac, `$GUEST_TEMP` — временный каталог гостя. Пути гостя с `C:\Users\lab\` — учётная запись гостя
`lab`, она разрешена.

## Privacy

См. `verification/privacy-scan.txt` и раздел 13 отчёта. Известные совпадения (уже в публичном коде репозитория, как в 4a): имя
файла `pcap-hashes-on-…txt` каждого прогона Windows (его задаёт `windows-suite`, в нём ssh-псевдоним хоста VM) и причина
`#[ignore]` теста `offline_generation_meets_80pct_of_oracle` (`rmasscan-core/tests/offline_gen.rs:36`, ssh-псевдоним хоста
стенда), которую печатают логи тестов. Пословный `grep` по двухсимвольным токенам совпал ещё в байтах заголовков записей двух
pcap (метки времени: `linux-banners-r1/runs/t01_tcp4/list/peer.pcap`, `linux-scan-control-r1/runs/sc03_retries/retries/peer.pcap`)
— случайные байты, не имя; `privacy-scan` заголовки записей не читает.
