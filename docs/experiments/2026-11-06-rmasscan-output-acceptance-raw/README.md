# Живая приёмка форматов вывода rmasscan (Linux) и регрессия автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-06-rmasscan-output-formats.md`, задача 9; спека
`docs/superpowers/specs/2026-11-06-rmasscan-output-formats-design.md`, §6.2–6.4. Все три каталога сняты на одном
коммите **C = `2b0e92ce7af3d0ba5ae68af881de22a0e99a3590`** (2026-11-06). Каждая сборка сделана из `git archive` этого
коммита (minipc и гость — полное дерево, home-pc и Mac — `rmasscan/`): release, `CARGO_INCREMENTAL=0`,
`RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. Хэши бинарников — в
`verification/binaries.sha256.txt`. Вердикты вынесли офлайн `output-verify` и `autodetect-verify`; для Windows —
`windows-verify`, который передаёт каталог autodetect целиком в `autodetect-verify`. После копии в репозиторий хэши
каждого прогона проверены повторно, и верификатор копии дал тот же вердикт байт в байт (sha256 ниже).

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-output-r1` | minipc, netns `wl-scan`/`wl-peer`, veth, стенд autodetect, C-оракул masscan 8e6b3b0 | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 21:17:25Z–21:22:32Z | `8752b7d60cbec6bbabf68895e8352293f886bc5da2241be63deb184f471b8b96` |
| `linux-autodetect-r2` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 21:22:48Z–21:24:23Z | `e546d9a310db98f558906288d4c7570cd6ca3d5920e3aab049a7dc08ee1f88aa` |
| `windows-autodetect-r2` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 21:22:30Z–21:53:23Z | `d70bd9ace70fded615d7cbf0752541329f89f22ab68c1e03125cc04593617874` |

macOS (`m1`): **NOT RUN**. Код ниже CLI этим этапом не менялся, а окно Mac требует `sudo` пользователя (спека §6.3).
Живой Ctrl-C на Windows: **NOT RUN**, консольное событие по ssh не доставить (спека §6.2). Обработчик покрыт
юнит-тестами, живые прерывания сняты на Linux (`o14`–`o16`).

## Что проверено

- `linux-output-r1`. C-оракул и rmasscan сканируют один и тот же ответчик (`198.18.0.2–.5`, порты 80 и 8080 открыты,
  443 закрыт) с одинаковым argv и пишут во все форматы masscan: `-oL`, `-oJ`, `--output-format ndjson`, `-oG`, `-oX`,
  `-oB`, `-oH`, `-oU`, JSON без `--show closed`, `-oL -` на stdout, `--interactive`. Записи равны оракулу после маски
  времени (порядок нормализован), заголовки равны после маски часов, записи равны ответам стенда и ответам на проводе.
  Подвал каждого формата rmasscan совпадает с подвалом, построенным из его же записей. Stdout молчит при `-o…`,
  строка статуса на stderr соответствует грамматике, `sent` равен числу SYN на проводе.
  `o12_nostatus` — только rmasscan. `o13_open_fail`: `-oL` в несуществующий каталог,
  `out: could not open file for writing`, exit 1, ноль кадров сканера.
  `o14`–`o16`: SIGINT через ~2 с; exit 0, `[+] finished: Stopped`, файлы JSON, XML и binary целые.
  `o17_readscan`: оба сканера читают оба `-oB` из `o06`, списки равны байт в байт, ноль кадров.
- **Подвал оракула.** masscan `8e6b3b0` не завершает ни один живой скан на этом стенде. Его поток приёма не
  возвращается на тихом линке, поэтому после окна ожидания он печатает
  `[-] Passed the wait window but still running, forcing exit...` и выходит с 0 (main.c:1489–1496). До
  `output_destroy` он не доходит, и в его файлах нет подвала. В `o01`–`o11` это записано как `oracle_forced_exit: true`
  в заметках прогона: нехватка подвала у оракула ожидаема, а без этой строки в stderr была бы INVALID. Байтовый
  паритет подвалов с C доказан офлайн эталонами `--readscan` (`rmasscan/tests/golden/formats`).
- `linux-autodetect-r2` и `windows-autodetect-r2` — повтор приёмки `2026-10-27-rmasscan-autodetect-acceptance-raw`
  (`linux-r1`, `windows-r1`) на C этого этапа. Теперь живой stderr CLI несёт строку статуса masscan, и верификатор
  autodetect читает его так, как показывает терминал (спека §6.3): фрагменты строки статуса перед `\r` есть в каждом
  скане, дошедшем до `[+] finished` (Linux `l01`–`l08` и `l11` — по 13 `\r`, Windows `w01`–`w04` — 20–21), и каждый
  из них разобран по грамматике, а не пропущен.

## Ворота

- Linux: `isolation.json`/`isolation-post.json` режима `autodetect` у каждого прогона; отмена стенда записана
  (`teardown.json`, `namespaces_left: 0`), её `lab_id` совпадает с `manifest.json`
  (`ead6c3b5-…6801` и `83083df6-…eaf8`); wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0`.
- Windows: в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1`
  home-pc 0 кадров. Preflight `w01` и `w06` назвал `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`.
  Гостевой Verify шёл с nonce и `record-guest`. Деплой: `deploy/deploy-manifest.json` (коммит C, бинарник
  лаборатории `8bf8c06b…fbae7`), хэши скриптов гостя записаны в `deploy/preflight-*.json`.
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.
- Privacy: `grep -ralwE` по именам хостов и учётным записям Mac, minipc, home-pc и гостя и по mDNS-суффиксам
  `_tcp`/`_udp` + `.local` (шаблон из `rmasscan/docs/rust-lab.md`) по каждому файлу трёх каталогов и `verification/`
  (`-a`, pcap тоже) — 0 совпадений. Пути вида `C:\Users\lab\…` относятся к учётной записи гостя `lab`, она
  разрешена. Полного `--iflist` нет нигде, только `iflist.json`.
- Стенды сняты: netns minipc удалены скриптом; `n2` — `vm-lab down` rc 0, `status` показывает `state: down` и все
  объекты MISSING (`verification/homepc-n2-status-after-down.json`).

## Версии

minipc Linux 7.0.0-38-generic, tcpdump 4.99.6; home-pc Linux 7.3.0-10-generic, QEMU 10.2.1; гость Windows
10.0.26300.9818, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`). `rmasscan.exe` собран на госте со статическим CRT и
`/DEPENDENTLOADFLAG:0x800` (`verification/guest-exits.txt`: `OK … 0800 Dependent Load Flag`, полный вывод — в
`guest-dumpbin-loadconfig-rmasscan.txt`). Mac только оркестрирует `windows-suite` по ssh: живых кадров с Mac нет,
`sudo` на Mac не использовался.

## verification/

- minipc: `cargo test --locked --workspace --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **1528 passed,
  0 failed**, 14 ignored (`minipc-test-ws.log`, `minipc-test-ws-exit.txt`). `cargo clippy --locked --workspace
  --all-targets -- -D warnings` — 0 (`minipc-clippy.log`, `minipc-exits.txt`). Логи окон:
  `minipc-linux-output-r1-window.log`, `minipc-linux-autodetect-r2-window.log`.
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута): `cargo test --locked --workspace --no-fail-fast` —
  **1428 passed, 0 failed**, 34 ignored; clippy `-D warnings` — 0 (`guest-test-ws.log`, `guest-clippy.log`,
  `guest-exits.txt`).
- Mac: только сборка оркестратора (`mac-build-lab.log`).
- `windows-autodetect-r2-suite.log`, `windows-autodetect-r2-verify.log`, `homepc-n2-status-*.json`,
  `hosts-versions.txt`, `binaries.sha256.txt`.

Логи `verification/` не входят в `hashes-before-copy.txt` прогонов; персональных путей и имён в них нет
(privacy-скан выше).

## Что было до этих каталогов (не закоммичено)

- **C = `8ad37b5`, первая попытка того же дня.** Окно `linux-output-r1` прошло чисто (`SUITE_RC=0`), но
  `output-verify` дал overall FAIL: PASS 9, INVALID 9, `safety_trips` []. Причина — тот же forced exit оракула:
  верификатор `8ad37b5` требовал от оракула целый подвал и сравнивал с ним подвал rmasscan. Окна регрессии autodetect
  по правилу остановки не запускались. Тогда же нашлись два дефекта тестов на этом C: clippy `check_out` (мёртвый код
  вне macOS) и тест `output_suite`, не работавший с путями Windows. Задача 8 исправила всё это в `2b0e92c`
  (`fix(lab): output-verify expects the oracle's forced exit, …`). Evidence той попытки в репозиторий не копировалось:
  оно снято на прежнем бинарнике лаборатории и не является доказательством для C (хранится вне репозитория, в
  нейтральном каталоге оператора).

## Отклонения

- `cargo test` шёл с `--no-fail-fast`, чтобы в логе были все тестовые бинарники, а не только те, что до первого
  упавшего.
- minipc, первая попытка тестов на C (`minipc-test-ws-attempt1-background.log`): 1526 passed, 2 failed. Упали
  `dump::tests::linux_wire_gate::real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate` и
  `dump::tests::sequence::a_complete_capture_is_acknowledged_finalised_and_valid` («tcpdump did not exit after
  SIGINT»). Причина в среде запуска: скрипт был запущен фоном (`nohup … &`) из неинтерактивного bash, и тот выставил
  SIGINT в SIG_IGN (`SigIgn: …07`). Поддельный `tcpdump` на `sh` унаследовал это и не может поставить на SIGINT
  `trap`. Повтор на переднем плане ssh-сессии (`SigIgn: …04`, SIGINT не игнорируется) — 0 failed. Живые окна по
  той же причине тоже шли на переднем плане ssh-сессии.
- Гость: экспорт без `.git`, поэтому перед тестами сделан `git init; git add -A`, как в прежних гостевых прогонах.
  Без индекса `rust_only::the_tracked_tree_has_no_interpreted_programs` строит список файлов обходом каталогов с `\`
  и не находит себя (попытка на `8ad37b5`).
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло одновременно с обоими окнами Linux на
  minipc. Стенды разные; через minipc шёл только ssh-трафик управления, кадры стенда netns его не видят.
- `n2` поднимал и снимал оператор через существующий `sudo -n` на home-pc. После `vm-lab up` VM перезапущена через
  `~/winvm/run.sh` с `lab.env`, затем `Start-Service w32time; w32tm /resync /force`, гостевой `Configure` и
  `record-guest --guest-json`.
