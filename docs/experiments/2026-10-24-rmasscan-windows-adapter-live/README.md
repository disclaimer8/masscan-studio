# Windows-адаптер Npcap: живые измерения (2B-Windows, задача 3)

Код: коммит `f51be48` (`feat(net): implement bounded Windows Npcap adapters`), собран и запущен из `git archive` ровно этого коммита на VM
(Windows 11 x64, Npcap 1.90, `AdminOnly=1`, виртуальный e1000e) на изолированном стенде `n2`. Это VM-корректность, не физический NIC и не пропускная способность.
Оркестрация: `tools/orch.sh` (перед КАЖДЫМ прогоном гостевой Verify, record-guest и полный `status` с `raw_run_allowed:true`; после прогона снова `status`; захваты на пире и на eno1;
eno1 везде 0 кадров). Пакеты шли только с `\Device\NPF_{C4617223-...}` (MAC 52:54:00:04:80:a9, 198.18.0.1) к 198.18.0.2; каждый кадр проходит `GuardTx`/`assert_lab_frame`.
Проверка: `shasum -a 256 -c MANIFEST.sha256` из этого каталога. Сырьё: `runs/eNN-*/` (гостевые логи, CSV, pcap пира и eno1, status до/после, qmp-events).

| Прогон | Что | Результат |
|---|---|---|
| e01 | TX handle с фильтром `ret #0`, 5000 отправок | `recv=0 drop=0` до и после (спайк без фильтра терял 37 264 из 38 094) |
| e02 | малый скан 6 портов (2 listener, 4 closed) ×2, через Engine | Completed, sent=6=tx_sent, SYN-ACK и RST разобраны, health Some(0), kernel_drops Some(0), rx_outgoing 0 (отсев в драйвере) |
| e03 | Stop на 1.5 с скана 1-2000 | Stopped, 30 мс от stop до исхода; tx_sent=450 = SYN у пира 450; после исхода 700 мс тишины |
| e04 | Pause на 4-й отправке, resume новой попыткой | Paused (3073 мс = TX stop + RX drain wait=3), 4+8 отправок = 12 проб без дублей |
| e05 | Uncertain (синтетический, через декоратор над реальным адаптером) | Failed(TxUncertain), sent=3, без checkpoint, 500 мс тишины |
| e06 | паника TX-потока | Failed(WorkerPanicked), без checkpoint, тишина, следующий скан проходит |
| e07 | 40 SYN: открытые/закрытые порты | своих кадров в RX 0; SYN-ACK 36, RST 20 дошли (не отфильтрованы) |
| e08 | реальные бюджетные вызовы, тишина | recv пустой n=430 p50 42 028 / p95 42 268 / max 42 420 мкс; health n=300 p50 9 / max 23 мкс; send n=150 p50 215 / p95 390 / max 512 мкс; >50 мс: 0 |
| e09 | скан при 60 kpps мусора (604 417 кадров) | Completed, обработано 418 455 кадров, потерь очереди NPF 0 |
| e10 | QMP `set_link lab0` down 10 с / up (сырые вызовы) | см. ниже |
| e11 | то же, через Engine | Failed(TxUncertain) через 95 мс после down, без checkpoint, тишина; после up скан проходит |

## Потеря линка гостя (блокировавший пункт)
`set_link lab0 down` переводит NIC гостя в `Disconnected` (20 отсчётов статуса). Во время down: `pcap_sendpacket` возвращает ошибку за 24 мкс (p50, max 240 мкс), адаптер
отдаёт `Uncertain` (159 из 160; одна первая отправка ещё `Sent`), recv пустой за 42 мс, health остаётся `Some(0)`, ошибок нет. После up ещё 8 отправок `Uncertain` (линк
поднимается с задержкой), затем `Sent`. Зависаний нет, максимум любого вызова 45.7 мс. Движок на Uncertain падает сразу (e11) и не повторяет отправку.
Ограничение: rc 0 при выключенном TAP на хосте (спайк) и потеря линка у пира-ноды по-прежнему не видны; здесь измерена именно потеря линка гостевого NIC.

## Removed interpreter-dependent tools

The repository allows no Python (CI guard `.github/workflows/language-guard.yml`, `scripts/language-guard.sh`). The files below invoked an interpreter and were deleted; the evidence data in this directory is unchanged. Each file is recoverable from git: `git show 5bcf8d5:docs/experiments/<path> | shasum -a 256` must print the recorded sha256. The corresponding lines were removed from `MANIFEST.sha256` (their hashes are recorded here instead).

| Path (under `docs/experiments/`) | Last commit containing it | Last changed in | sha256 |
|---|---|---|---|
| `2026-10-24-rmasscan-windows-adapter-live/tools/flood.py` | `5bcf8d5` | `3089832` | `38baeb338e8ef69a1580e05a30fd91a9c2e99c4b515219d25fb21dec2a0bb00f` |
| `2026-10-24-rmasscan-windows-adapter-live/tools/listener.py` | `5bcf8d5` | `3089832` | `1de47b7c9da8c221911544fb6c8c0d25d277226b8d5f253feee026f8864dbe4c` |
| `2026-10-24-rmasscan-windows-adapter-live/tools/qmp_link.py` | `5bcf8d5` | `3089832` | `af3ecbe1c8d14376952832cbdfdeac5faf79586e4c6c9ae81624e0adfebdbf6a` |
| `2026-10-24-rmasscan-windows-adapter-live/tools/orch.sh` | `5bcf8d5` | `3089832` | `c0c946f6e11cfa81fc8790b02d020d6c0d376dc916fc959aa6e7cc45d93a2cfd` |
