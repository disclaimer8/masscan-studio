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
* Слушатели пира заданы явно (`scripts/windows_wire_peer.py listen`): открыты 80, 443, 8000-8007; порт 8099 «немой» (очередь accept заполнена, SYN отбрасывается);
  остальные получают RST ядра. Порты 8080/8081 не используются: на них висит чужой слушатель более ранней задачи (pid 4038625), я его не трогал.

## Состав
* `functional/manifest.json`: коммит, sha256 exe, binding, oracle. `functional/fixtures/`: эталоны C (+ `manifest.json` с sha256).
* `functional/runs/<tag>/`: на каждый прогон `argv.json` (точный argv-массив), `run.json` (JSON harness-а), `peer.pcap`, `eno1.pcap`,
  `capture.json` (фильтры, статистика tcpdump, счётчики lab0, sha256/размер/число кадров, снятые на home-pc ДО копирования), `status-pre/post.json`,
  `guest-verify.json`, `listeners.json`, `meta.json`, `pcap-hashes-on-home-pc.txt`, при подмене ответов `injector.json`; для pause-ноги `checkpoint.bin`.
* `functional/runs_discarded/`: прогон, признанный INVALID и перезапущенный (сохранён).
* `functional/verdict.json`: вывод офлайн-проверяльщика `python3 scripts/windows_wire_verify.py --dir functional` (29 вердиктов).
* `functional/logs/`: журналы оркестратора. `verification/`: clippy и `cargo test --workspace` на VM для этого коммита.

## Проверка
`shasum -a 256 -c MANIFEST.sha256` из этого каталога; `python3 -I rmasscan/scripts/windows_wire_verify.py --dir functional` (Mac/Linux/Windows, без Npcap).
Из текстовых файлов убраны имена домашних каталогов (`/home/a1` -> `$HOME`, путь рабочей копии -> `$REPO`); pcap не менялись.

## Что было INVALID
`runs_discarded/x01_foreign_replies.run1.*`: tcpdump получил 96 кадров, записал 94 (счётчики lab0: 96). Неполный захват -> INVALID, прогон повторён без правок кода (PASS).
Причина: хвостовые кадры, не выданные из кольца TPACKET_V3 к моменту SIGINT. Оркестратор не ждёт после «тишины» таймаута блока libpcap; запись в замечаниях отчёта.
