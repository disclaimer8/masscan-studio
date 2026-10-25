# Windows VM: функциональная wire-приёмка и pause/resume (2B-Windows, задача 4, часть A)

Сырые данные. Итоговый отчёт пишет задача 5. Это VM-корректность на изолированном стенде `n2`, не физический NIC и не пропускная способность.

* Код: коммит `1a446c594d86db52fbfa9a07962dc8cc1b662ca9` (`test(net): Windows wire suite and offline verifier`, поверх `e809734`).
  `wire_scan.exe` собран из `git archive` ровно этого коммита (`RMASSCAN_SOURCE_COMMIT` = полный sha, `+crt-static`, release),
  tar-источник: `git archive --format=tar 1a446c5 rmasscan`, sha256 `1aaa403d17969f497a3f40428949aa9fde278a84997fdfd85f6b86b18908bedd`;
  sha256 `08096f115dd95e982b0c635e3ff14185493d65418ea8576ff32379dbc1d4580c`; тот же sha в `run.json.identity.binary_sha256` каждого прогона.
* Binding (одинаков у Windows-прогонов и C-эталонов, без нормализации): `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}`,
  198.18.0.1, MAC 52:54:00:04:80:a9, пир 198.18.0.2 / lab0 MAC 02:57:4c:3d:2e:9b, seed 1, rate 100, wait 3, retries 0.
* Эталон C: оригинальный pinned masscan (ревизия `8e6b3b0c07a81e8ea61d557c06134a21a6881614`, дерево чистое, не `--offline`-копия),
  sha256 бинарника `8afc8ec81f2e051389116908b01a4482b42e020bc48254585b7dcca4b25e2a3e`; снят на `minipc` в запечатанных netns+veth (`scripts/wire-lab.sh` с `WIRELAB_*`), `fixtures/`.
  Каждый случай снят дважды, оба прогона C побайтно равны. Пространства `minipc` убраны (`fixtures/cleanup.txt`).
* Слушатели пира заданы явно (тогда скриптом пира, сейчас `rmasscan-lab peer listen`): открыты 80, 443, 8000-8007; порт 8099 «немой» (очередь accept заполнена, SYN отбрасывается);
  остальные получают RST ядра. Порты 8080/8081 не используются: на них висит чужой слушатель более ранней задачи (pid 4038625), я его не трогал.

## Состав
* `functional/manifest.json`: коммит, sha256 exe, binding, oracle. `functional/fixtures/`: эталоны C (+ `manifest.json` с sha256).
* `functional/runs/<tag>/`: на каждый прогон `argv.json` (точный argv-массив), `run.json` (JSON harness-а), `peer.pcap`, `eno1.pcap`,
  `capture.json` (фильтры, статистика tcpdump, счётчики lab0, sha256/размер/число кадров, снятые на home-pc ДО копирования), `status-pre/post.json`,
  `guest-verify.json`, `listeners.json`, `meta.json`, `pcap-hashes-on-home-pc.txt`, при подмене ответов `injector.json`; для pause-ноги `checkpoint.bin`.
* `functional/runs_discarded/`: прогон, признанный INVALID и перезапущенный (сохранён).
* `functional/verdict.json`: вывод офлайн-проверяльщика (тогда скриптовая версия, сейчас `rmasscan-lab windows-verify --dir functional --out functional/verdict.json`) (29 вердиктов).
* `functional/logs/`: журналы оркестратора. `verification/`: clippy и `cargo test --workspace` на VM для этого коммита.

## Проверка
`shasum -a 256 -c MANIFEST.sha256` из этого каталога; `rmasscan-lab windows-verify --dir functional` (Mac/Linux/Windows, без Npcap; скрипт, которым это проверялось раньше, удалён из репозитория, поведение перенесено в Rust-проверяльщик).
Из текстовых файлов убраны имена домашних каталогов (`/home/a1` -> `$HOME`, путь рабочей копии -> `$REPO`); pcap не менялись.

## Что было INVALID
`runs_discarded/x01_foreign_replies.run1.*`: tcpdump получил 96 кадров, записал 94 (счётчики lab0: 96). Неполный захват -> INVALID, прогон повторён без правок кода (PASS).
Причина: хвостовые кадры, не выданные из кольца TPACKET_V3 к моменту SIGINT. Оркестратор не ждёт после «тишины» таймаута блока libpcap; запись в замечаниях отчёта.

## Fix round 1
* `functional/verdict.json` is regenerated with the fixed verifier (commit `3126206`): it now also verifies `runs_discarded/` (listed under `discarded`, the INVALID x01 run) and asserts discarded == injected for the foreign runs (80 == 80, duplicates are genuine retransmits). Result unchanged: 29 PASS, overall PASS. The part A captures predate the end marker, so the verifier treats them as `capture_schema` 1 (no end-marker check; completeness still rests on stats, counter window and hash).
* `functional-r1-smoke/`: ONE live smoke run (`c02_one_addr_port_rst.run1`) of the new orchestrator under the full raw-run rules, exe built from `3126206` (capture_schema 2: `--immediate-mode`, end marker before SIGINT). Its run verdict is PASS; the other planned runs are NOT RUN by design, so its overall verdict is not PASS.

## Fix round 2
* Verifier re-run with the round 2 rules (capture_schema per run, behaviour failures, strays). `functional/manifest.json` now labels part A `capture_schema` 1. Part A: unchanged, 29 PASS, overall PASS, discarded INVALID x01 run listed, no behaviour failure; x01 runs: discarded 80 == injected 80 + strays 0.
* `functional-r1-smoke/` CHANGED: its run is now INVALID (`run capture_schema 1 < directory 2`). The run was captured by the round 1 orchestrator, which recorded the schema only in the directory manifest and not in `capture.json`; it did have `--immediate-mode` and the end marker (its checks passed in round 1). I did not edit its `capture.json` to add the field. A fresh smoke with the round 2 orchestrator would be needed for a PASS verdict.

## Fix round 3
Verdicts regenerated with the round 3 verifier (argv.json check, strays incl. broadcast, NOT RUN for missing continuous captures). Unchanged: `functional` 29 PASS / overall PASS; `functional-r1-smoke` run INVALID (no per-run capture_schema). No raw evidence file was edited.

## Rust harness and reruns (F4)
* Каталоги `functional-r2/` (часть A) и `failure-r1/` (часть B) создаёт `rmasscan-lab windows-suite` (план `functional` — 24 прогона, `failure` — 18). Каждый содержит `manifest.json`, `fixtures/`, `runs/`, `runs_discarded/`, `deploy/` (копия deploy-манифеста, байты гостевых скриптов, `preflight-<run>.json` с хэшами бинаря home-pc, скриптов и измеренным расхождением часов), `verdict.json`, свой `README.md` и `MANIFEST.sha256`. Процедура сборки и развёртывания: `rmasscan/docs/rust-lab.md`, раздел «Deployment for the live Windows rerun».
* Эталоны C переиспользуются: `functional/fixtures` передаётся в `--fixtures` и для части A, и для части B (binding одинаков); заново эталоны не снимаются.
* Оговорка по части A (`functional/`): её прогоны сняты до цепочки nonce (X1), поэтому нога «гостевой Verify» шлюза raw-run для них не доказана по каждому прогону (проверяльщик читает их как capture_schema 1, без этого требования). Доказательство даёт только `functional-r2/` и `failure-r1/` (capture_schema 3: nonce, хэши, код выхода Verify обязательны).
* Скрипты, которыми велись первые прогоны (оркестратор, проверяльщик, пир), удалены из репозитория; их история остаётся в git (до коммита `123fe76`). Исторические инструменты в других каталогах сырых данных удалены вместе с записью пути, последнего коммита и sha256 в их README.

## Rust harness rerun (2026-10-25)
Parts A and B were rerun with the Rust lab tool (`rmasscan-lab windows-suite`, `rmasscan/docs/rust-lab.md` steps 1-8). They used code commit `9ecbe32`, capture_schema 3 and the per-run raw gate (guest Verify with nonce, record-guest, full status raw_run_allowed=true). Each directory has its own `README.md`, `verdict.json` and `MANIFEST.sha256`:
* `smoke-rust-9ecbe32/`: one smoke run (`c01_one_addr_port_synack.run1`), run verdict PASS; the other planned runs are NOT RUN by design.
* `functional-r2/`: part A, 24 runs, overall **PASS** (29 PASS).
* `failure-r1/`: part B, 18 runs, overall **PASS** (19 PASS). Its two flood captures are stored as `peer.pcap.gz`, so run `gunzip -k` before re-verifying (see its README).
eno1 shows 0 lab frames in all 43 committed runs (each `eno1.pcap` is a 24-byte header). Unlike `functional/` (capture_schema 1), these runs carry the per-run guest-gate proof.
The root `MANIFEST.sha256` covers the files above plus each new directory's `MANIFEST.sha256`; run `shasum -a 256 -c MANIFEST.sha256` inside each new directory to check its contents.
