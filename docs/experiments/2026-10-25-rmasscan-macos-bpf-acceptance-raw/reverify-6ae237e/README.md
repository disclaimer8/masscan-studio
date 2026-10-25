# Повторная верификация архива приёмки macOS BPF, раунд 2 (post-merge fix)

Верификатор: `rmasscan-lab macos-verify` из коммита `6ae237e` ветки `fix/rmasscan-2c-review-11c6764` (база `2625903`).
Каталоги `functional-r1`, `perf-r1`, `failure-r1` лежат рядом и не менялись (`shasum -c MANIFEST.sha256` проходит).
Метод тот же, что в [`reverify-627776f`](../reverify-627776f/README.md): копия каталога вне репозитория, в копии `gunzip` всех
`*.pcap.gz` (sha256 распакованных файлов равны `PCAP-GZ-ORIGINALS.txt`), затем `macos-verify --dir <копия> --out <файл>`.

| Каталог | Архивный вердикт | `627776f` | `6ae237e` |
|---|---|---|---|
| `functional-r1` | PASS 29/29 | PASS 29/29 | PASS 29/29 |
| `perf-r1` | PASS 21/21, rate gates MET | то же | то же |
| `failure-r1` | 17 PASS + `linkloss` INVALID (предварительное правило) | то же | то же |

Тексты вердиктов (`*.verdict.txt`) побайтно равны `reverify-627776f`. JSON отличается только в `failure-r1`: у `stop_silent` и `stop_load`
добавилась одна проверка (+1) «every genuine reply on the wire well before the Stop request is a result», она PASS (3 из 3 RST пришли за
501–2504 мс до запроса Stop и есть среди результатов). `reverify-627776f/` оставлен для истории, не заменён, потому что его JSON не
идентичен.
