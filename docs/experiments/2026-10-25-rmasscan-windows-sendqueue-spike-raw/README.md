# Сырьё спайка sendqueue (задача 3)

Отчёт: [`../2026-10-25-rmasscan-windows-sendqueue-spike.md`](../2026-10-25-rmasscan-windows-sendqueue-spike.md).
Проверка целостности: `shasum -a 256 -c MANIFEST.sha256` из этого каталога.

- `runs/<run>/` один прогон = одна живая отправка. Файлы:
  - `status-pre.json`, `status-post.json` (и `status-link-restored.json` в r13): полный `vm-lab status`, `raw_run_allowed: true`, nonce гостевого Verify;
  - `guest-verify.json`, `record-guest.json`: гостевой Verify с nonce прогона и его запись на `home-pc`;
  - `capture-filters.txt`, `peer.pcap` (или `peer.excerpt.pcap` + `peer.pcap.orig.txt`), `peer.err`, `eno1.pcap` (24 байта = 0 кадров), `eno1.err`;
  - `flood.json` / `linkloss.json`: отчёты инструментов пира (`rmasscan-lab peer flood|linkloss`);
  - `guest-out/*.csv` (`t_ms,n,bytes_queued,bytes_sent,dur_us` по каждому transmit, и сводные CSV partial / stop / process), `guest-out/*.log` (KV-строки теста), `guest-out/*.run.txt` (exe, sha256 exe, NIC до/после);
  - `home-pc.sha256`: sha256 всех файлов, взятые на `home-pc` до копирования (в текстах домашний каталог `home-pc` потом заменён на `$HOME`, поэтому их хэши в этом списке уже другие; pcap не менялись), `copy-verify.txt`: результат сверки копии с этим списком до правки путей;
  - `analysis.txt`: проверка «ровно один раз» по pcap (ad hoc скрипт оператора, исходник не хранится), счётчики приёма NIC гостя.
- `tools/`: `orch.sh` (оркестратор на `home-pc`), `run_live.ps1` (гость), `collect.sh` (копирование и обрезка на Mac), `env.ps1` (версии на госте).
  Сбор на Mac делался эквивалентным циклом команд из `collect.sh`.
- `guest-env.txt`, `home-pc-env.txt`: версии окружения.
- pcap пира больше 40 МБ не хранятся (полные файлы остаются на `home-pc` в `~/winvm/sq-ev/<run>/`): размер и sha256 в `peer.pcap.orig.txt`, первые 2000 пакетов в `peer.excerpt.pcap`.
- Прогоны r00-r04 собраны из коммита `61c1126`, r05-r15 из `53afec8`, r16-r17 из `3954b14`.
