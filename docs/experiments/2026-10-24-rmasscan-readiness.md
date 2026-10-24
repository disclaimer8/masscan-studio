# rmasscan: перечень готовности и долга интеграции/поставки

Дата: 2026-10-24. Документ только фиксирует проверенное и открытое. Он ничего не
закрывает: ни Windows, ни macOS, ни Studio, ни лицензионный gate. Исходники,
Cargo license-поля, релизы и spikes-дерево этой задачей не менялись.

Состояние: ветка `feat/rmasscan-stage2b-linux`, база документа — `e5d6326`
(HEAD до этого docs-коммита). Источник перечня возможностей по слоям —
[спецификация, §0.2](../superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md);
здесь он не дублируется. Контракты RX integrity/TX stall — там же, §0.1.

## 1. Итоги по направлениям

| Направление | Статус | Доказательство | Точный блокирующий gate |
| --- | --- | --- | --- |
| Linux merge readiness | **OPEN** | Код и контракты: `364ee49`, `c31ae16`; приёмка Linux измерена на коммите кода `27e3042`, evidence `8479ff2`, [раздел отчёта](2026-10-23-rmasscan-stage2b-linux.md); review Задач 1-5 и итоговое review ветки пройдены (замечания закрыты) | Остаётся только: (1) CI на точном запушенном HEAD зелёный (**NOT RUN**, push не разрешён); (2) решение о merge принимает пользователь отдельно |
| Windows correctness | **NOT RUN** | Raw I/O Windows не запускался; Windows-кода адаптера нет. План: [Windows](../superpowers/plans/2026-10-24-rmasscan-stage2b-windows.md) | Windows 11 x64 + Npcap с реальными TX/RX, byte parity, pause/resume, Stop ≤1 с, контракты RX health/TX stall на адаптере. Хоста нет (см. 3.1) |
| macOS correctness | **NOT STARTED** | Нет плана и кода BPF-адаптера | Отдельный план; аппаратная проверка macOS; те же контракты потерь/остановки |
| Studio integration | **OPEN** (pinned engine устарел) | Раздел 2 | Обновить vendor до актуального engine/net; настоящий Scan вместо offline-preview/fake-process; runner gate (раздел 5); UI-паритет |
| Distribution | **OPEN** | Раздел 4 | Решение по лицензиям (раздел 4.3); воспроизводимый source/binary bundle; повторная проверка ad-hoc подписи Mac |

Слои, которые никогда не смешиваются: offline-тесты, CI-сборка, lab wire (netns/veth),
физический NIC, UI-приёмка. Физический NIC не проверен нигде (ни Linux, ни Windows).

### 1.1. Linux: что именно измерено

Результаты ниже относятся к чистому коммиту кода `27e3042` (`rmasscan/` не менялся до HEAD
этой записи, кроме теста `tx_stall.rs`); evidence-коммит `8479ff2`. Review Задачи 4 пройдено после fix round;
прогон на `ee51a19`/`eb8812a` заменён (superseded) и не является текущим результатом. Подробности и сырые данные:
[отчёт Linux, раздел «Fix round 1: повторный прогон на `27e3042`»](2026-10-23-rmasscan-stage2b-linux.md),
[сырые данные](2026-10-24-rmasscan-linux-acceptance-raw/round1-27e3042/).

- Functional: 141 pass / 0 fail / 0 skip.
- Performance: 40 из 40 точек VALID; Rust `rx_health` `kernel_drops` = 0 в 20 из 20 прогонов; медианы Rust/C по
  скоростям 100/1000/10000/100000 pps: 1.016/1.000/1.000/1.004.
- Воспроизведённое переполнение RX даёт `Failed(RxLoss { kernel_drops: 173 })`, rc 3, без checkpoint.
- CI для точного HEAD: **NOT RUN** (push не разрешён). Зелёный прогон старого PR #8
  (`df53e6d`) — не CI этого HEAD.
- Не проверено: физический NIC, >100k pps, Windows, macOS, UI.

## 2. Studio: закреплённый snapshot

Источники (read-only): `cross-platform/vendor/rmasscan-core/SNAPSHOT.json` в spikes-дереве
Studio (`feat/cross-platform-spikes`, грязное, чужая работа) и опубликованные pre-release
`engine-preview-2026-10-23`, `process-preview-2026-10-23`, `ui-preview-2026-10-23`.

### 2.1. Хэши vendor против закреплённых git-объектов

Проверка шла против git-объектов `e195df3983b51f408264e471a23119af373f2848` (коммит
`test(core): proptest for permutation invariants and parser robustness`, предок текущего HEAD),
а не только против manifest:

- 11 файлов `src/*.rs`: SHA-256 `git show <rev>:rmasscan/crates/rmasscan-core/<file>` совпал с
  SNAPSHOT.json и с файлами рабочего vendor-каталога: MATCH 11/11. Те же 11 файлов в source ZIP
  engine-preview совпали с git-объектами.
- `LICENSE` (`0d96a4ff68ad…`): совпал с `rmasscan/LICENSE` текущего HEAD; в vendor он заявлен как
  взятый из C-upstream (`8e6b3b0`). Объект upstream в этом клоне недоступен, поэтому происхождение
  от upstream по самому upstream-объекту здесь **не** проверено; проверен только факт совпадения с
  `rmasscan/LICENSE`.
- `Cargo.toml` vendor (`51fc03a3f832…`) намеренно отличается от workspace-манифеста в git
  (`bd38287d7a5f…`): автономный манифест, заявлено в SNAPSHOT.json. Его содержимое сверено только
  с manifest, не с git-объектом.

### 2.2. Что в snapshot отсутствует

Закреплённая ревизия `e195df3` содержит из rmasscan только `rmasscan-core` и `rmasscan-cli`. В ней нет
`rmasscan-engine`, `rmasscan-net`, `arp`/`probe` модулей core (vendor `lib.rs` перечисляет 10 модулей без
них), RX health, TX-stall watchdog, Linux AF_PACKET. От текущей ветки её отделяют 45 коммитов; в
`rmasscan-core` изменились 16 коммитов (+1426/−43 строк в `src/` по 9 файлам). Актуального engine/net в
Studio нет. Обновление vendor и сборку нового preview оставить отдельному интеграционному этапу
(этой задачей не выполняется).

### 2.3. Разделение возможностей (не объявлять одно другим)

| Пара | Состояние |
| --- | --- |
| ARP codec / ARP resolver | codec есть в core текущей ветки (отсутствует в pinned snapshot); resolver и discovery шлюза нет нигде |
| `paused.conf` library / import UI | парсер в core (библиотека); пользовательского import UI нет |
| offline preview / raw Scan | Studio-preview готовит задание, исключения, число целей и первые 32 элемента порядка без пакетов; сетевого Scan нет. Release-текст engine-preview: «No real scan packets» |
| fake-masscan process | синтетический helper с фикстурами документационного диапазона; не Rust-engine |

### 2.4. UI: незакрытые взаимодействия (Slint, Qt не нужен)

Выбран только Slint; Qt/CXX-Qt исключены. Не закрыты и не доказаны: per-cell interactions таблицы,
native menu, keyboard и IME, frame timing. Release `ui-preview` сам помечает общий A1/A2 как
INCONCLUSIVE; Windows-запуск не проверен (Wine не засчитывается), Ubuntu 26.04 Wayland benchmark неполный.

## 3. Windows и macOS

### 3.1. Windows

- Windows + Npcap хоста нет. На home-pc (Ubuntu, QEMU/KVM) готовится VM Windows 11, ISO ещё нет: загрузка
  через Mido 2026-10-24 10:21 вернула HTTP 404 от Microsoft. Даже с VM NIC виртуальный, поэтому
  физический паритет остаётся **NOT RUN**.
- План Windows обновлён: [Задача 0](../superpowers/plans/2026-10-24-rmasscan-stage2b-windows.md) теперь
  ссылается на закрытые задачи [плана ремедиации](../superpowers/plans/2026-10-24-rmasscan-review-remediation.md)
  и включает контракты, которым должен удовлетворять адаптер. Предыдущие команды и цифры не являются
  свежим прогоном.
- Windows CI-сборка (`windows-2022`) и offline-тесты не доказывают raw I/O.

### 3.2. macOS

BPF: не начато. Нужны отдельный план, аппаратная проверка, те же контракты потерь/остановки. Ad-hoc подпись
Mac-приложения проверяется повторно перед GUI-поставкой.

## 4. Поставка и лицензии

Лицензионной готовности этот раздел не утверждает и юридического вывода не делает. Cargo license-поля
не менялись.

### 4.1. Опубликованные pre-release (GitHub `disclaimer8/masscan-studio`, isPrerelease=true)

Все три: tag указывает на базу `b02dd2968563bd4af952748272f2d7bb92568281`; исходники — несохранённое
состояние, авторитетен приложенный source ZIP (сказано в release-тексте и manifest).

| Релиз | Source ZIP SHA-256 | Что внутри |
| --- | --- | --- |
| engine | `defaf777e485…` | 53 файла; Studio-код, `Cargo.lock`, `scripts/`, `vendor/rmasscan-core` (src + LICENSE + SNAPSHOT.json + автономный Cargo.toml), docs |
| process | `df4812cb385a…` | 31 файл, без engine |
| ui | `59e39cae264b…` | 24 файла, без engine |

Содержимое просмотрено списком (`unzip -l`) и чтением файлов; ничего из архивов не запускалось.

### 4.2. Проверка source ZIP против требований

| Требование | engine | process / ui |
| --- | --- | --- |
| `Cargo.lock` | есть (`1303de69b88e…`, slint 1.18.1) | есть; хэш совпал с manifest |
| build scripts | `build.rs`, `scripts/build-release-preview.sh`, `xtask` есть | есть |
| manifests | `Cargo.toml` всех crate есть | есть |
| собственный код Studio | есть | есть |
| хэши исходников в manifest | **нет** (в engine `build-manifest.json` нет `source_sha256`) | есть; 31/31 и 24/24 совпали, лишних файлов нет |
| vendor LICENSE | есть (AGPL-3.0 text, = `ENGINE-LICENSE.txt` в Windows ZIP) | не применимо (engine не включён) |
| vendor NOTICE (MIT-часть `util-checksum.c`) | отдельного NOTICE **нет**; MIT-атрибуция есть только комментарием в `checksum.rs` | не применимо |
| инструкция восстановления | `README.md` и `PLATFORM-VERIFICATION.md` описывают сборку на Rust 1.99.1 по lockfile; отдельной пошаговой инструкции «восстановить именно этот бинарник» нет | то же |
| исходники зависимостей (crates) | не приложены (только lockfile) | то же |
| бинарник связан с исходником | `Masscan-Studio-Preview.exe` `efa36ef7de64…` и `fake-masscan.exe` `51378584f71f…` из Windows ZIP совпали с `ui_sha256`/`fixture_sha256` manifest; **пересборка из ZIP не выполнялась**, воспроизводимость не доказана | process: хэши EXE совпали с manifest |

Наличие source ZIP не считается доказательством полной лицензионной готовности; его частичная полнота
также не утверждается за пределами таблицы. Не проверено: полнота notices зависимостей (561 запись в
lockfile engine), соответствие ZIP бинарнику побайтно.

Дополнительные факты: crate `scan-engine` объявляет `license = "AGPL-3.0-only"`, остальные Studio crates
(`scan-core`, `scan-process`, `spike-data`, `slint-table`, `xtask`) поля license не имеют. Это зафиксировано
как наблюдение, не как исправляемый дефект в рамках задачи. Process и ui релизы не содержат файлов лицензий
в Windows ZIP (в engine ZIP есть `ENGINE-LICENSE.txt`).

### 4.3. Решения, которые нужны до следующей поставки (OPEN)

1. Условия для объединённого Studio + AGPL engine (в одном исполняемом файле/процессе против отдельного
   процесса): кто лицензиат, что публикуется, какой исходник сопровождает бинарник.
2. Вариант лицензирования Slint для точной версии из `Cargo.lock` Studio (в проверенных lock-файлах —
   `slint 1.18.1`). Условия этой версии в рамках задачи не проверены (кэш crates недоступен).
3. Notices зависимостей: инструмент/процедура, содержимое для бинарной поставки.
4. Полнота и воспроизводимость source ZIP для уже выданного бинарника (хэши исходников, vendor NOTICE,
   исходники зависимостей или инструкция их получения, пересборка и сравнение).
5. Публичный выпуск и подпись не разрешаются изменением Cargo license-поля; отдельное решение пользователя.

AGPL-3.0 для порта принят пользователем; Nmap остаётся внешним инструментом.

## 5. Будущий gate: runner

Состояние: **OPEN, не решено, не реализовано.** Требования описаны в
[спецификации, §5–6](../superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md). Закрытие gate
требует проверки всей схемы целиком по каждой ОС:

- владение raw socket / handle: какой процесс его открывает и кому передаёт;
- объём кода под повышенными правами, измеримо;
- feasibility privilege-drop на каждой ОС (Linux capabilities, macOS BPF-устройства, Windows с драйвером Npcap);
- аутентифицированный IPC и смена версии;
- lifetime: поведение при смерти scanner и при смерти runner; смерть scanner не считается решённой, пока
  не проверена вся схема, включая Windows-драйвер и возможные дочерние процессы;
- durable checkpoint ACK: checkpoint принят хранилищем до подтверждения пользователю.

Ни один из пунктов здесь не заявлен как решённый.

## 6. Что этот документ не закрывает

Windows/macOS/UI/licensing gates остаются открытыми. Очередь дальше: Windows/Npcap, macOS BPF, сетевая
интеграция (discovery/ARP, network identity, sleep/VPN), runner/Studio, поставка.
