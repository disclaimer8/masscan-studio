# Порт masscan на Rust — этап 0 (подготовка) — план реализации

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ ПОД-НАВЫК: используйте
> superpowers:subagent-driven-development (рекомендуется) или
> superpowers:executing-plans для реализации по задачам. Шаги помечены
> чекбоксами (`- [ ]`). Коммиты исполнитель делает **только с согласия
> пользователя** (см. примечание в каждой задаче).

**Goal:** Подготовить изолированный Rust-workspace порта, правило «без C в
сборке» с автоматической проверкой, CI на трёх ОС без raw-сокетов, и
однократно собрать C-оракул masscan на Ubuntu, зафиксировав golden-фикстуры
`-sL`/`--echo` для офлайн-сверки на этапе 1.

**Architecture:** Порт живёт в **отдельном** workspace
`rmasscan/` в корне репозитория studio (решение автора плана, обоснование
ниже), с crates `rmasscan-core` (чистая логика, `#![forbid(unsafe_code)]`) и
`rmasscan-cli` (тонкий CLI-двойник для дифференциальных тестов). Оракул C
masscan собирается один раз на Ubuntu и в репозиторий попадает только как
текстовые фикстуры и манифест; сам C-бинарник в репозиторий и в CI не
тянется.

**Tech Stack:** Rust 1.99.1 (локально подтверждён на macOS arm64), edition
2024, resolver 3. Зависимости (pure Rust, проверены по crates.io на
2026-10-23, совместимы с edition 2024): `clap =4.6.7` (derive),
`siphasher =1.0.4`, `serde =1.0.229`, `serde_json =1.0.154`,
`thiserror =2.0.21`, dev: `proptest =1.12.0`, `criterion =0.8.2`.
Dev-инструмент `cargo-deny 0.20.2` (ставится в CI через `cargo install
--locked`, в графе зависимостей продукта отсутствует).

**Spec:** `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`
(далее «спека»; особенно §3 карта подсистем, §4 инварианты, §6 правила «без
C», §7 стратегия проверки, §9 этапы 0 и 1). Исходники masscan:
`/Users/denyskolomiiets/masscan`, HEAD `8e6b3b0`, версия `1.3.9-integration`.

## Решение автора плана: где лежат crates порта

**Отдельный workspace `rmasscan/`, а не добавление crates в существующий
`cross-platform/`** (каталог `cross-platform/` и связанные документы studio лежат
неотслеживаемыми в основной копии studio и в этой ветке отсутствуют). Обоснование: правило «без C в сборке» (спека §6.1)
проверяется над всем графом зависимостей workspace через `cargo deny` и
`cargo tree -e build`. Существующий workspace `cross-platform/` содержит
Slint-спайк (`spikes/slint-table`), чей `Cargo.lock` уже тянет
`cc`, `bindgen`, `pkg-config`, `yeslogic-fontconfig-sys` и прочие C-сборочные
crates (проверено: `grep -E '^name = "(cc|bindgen|pkg-config|...-sys)"'
cross-platform/Cargo.lock`). Если положить порт туда, обще-workspace-ная
проверка «без C» будет либо падать на Slint, либо её придётся ослаблять до
пофайловой, что хрупко. Отдельный workspace даёт **чистый граф**: `cargo tree
-e build` и `cargo deny` над `rmasscan/` не видят Slint вовсе. Цена — второй
`Cargo.lock` и второй CI-набор; на этапе 3 studio-runner подключит
`rmasscan-core` как `path`-зависимость. edition 2024 / resolver 3 берутся те
же, что в `cross-platform/Cargo.toml`.

## Global Constraints

Эти требования неявно входят в каждую задачу этого файла и этапа 1.

- Целевые ОС: macOS 14+ arm64, Windows 11 x64, Ubuntu 24.04 x64 (спека §5).
  Этап 0 проверяется на всех трёх в CI; raw-сокеты не используются.
- Без C/C++ в нашем коде и в графе сборки: нет crates с `cc`, `cmake`,
  `bindgen` (сборочный), `pkg-config` на C-библиотеки, нет обязательной
  libpcap (спека §6.1). Исключения — только §6.3 (ядро/системные библиотеки
  ОС, toolchain, на Windows Npcap — всё это на этапах 0–1 не подключается).
- `rmasscan-core`: `#![forbid(unsafe_code)]` (спека §13, мера по TCB).
- Версии зависимостей зафиксированы точно (`=x.y.z`), как в соседнем плане
  `2026-10-23-a1-ui-spikes.md`. `Cargo.lock` коммитится.
- Лицензия порта — AGPL-3.0 (спека §8.1, ответ пользователя на вопрос 1);
  в каждом портированном модуле сохраняется копирайт Robert David Graham и
  ссылка на источник.
- О пользователе — «пользователь», без местоимений, указывающих на пол.
- Никаких сетевых сканов. Сборка оракула и прогон `-sL`/`--echo` пакетов не
  шлют (спека §4.8): это не сетевой скан.

## Review Focus

Классы входных данных, которые спека подразумевает, но happy-path тесты не
трогают; каждая строка закрыта тестом в указанной задаче (здесь на этапе 0 —
инфраструктурные, предметные вынесены в этап 1).

1. Граф сборки может «протащить» C-crate транзитивно через будущую
   зависимость — проверка «без C» должна ловить это автоматически, а не
   глазами (Задача 2: `cargo deny` + `cargo tree -e build` в CI, тест на
   заведомо-запрещённом crate).
2. CI на Windows/macOS может «молча» пропустить проверку «без C», если она
   написана только под Linux-шелл (Задача 3: шаг проверки одинаков на трёх
   ОС, без bash-измов).
3. Golden-фикстуры без манифеста происхождения бесполезны для сверки
   (Задача 4: манифест с командой, хэшем бинарника и версией; тест этапа 1
   читает манифест и падает, если его нет).
4. Оракул, собранный не из зафиксированного HEAD, даёт неверный эталон
   (Задача 4: фиксация `git rev-parse HEAD` == `8e6b3b0…`, прогон отказывает
   при расхождении).
5. Доступ к Ubuntu-машине неизвестен — угадывание SSH-хоста приведёт к
   действию на чужой машине (Задача 0: исполнитель спрашивает доступ, не
   угадывает).

---

## Задача 0: Запрос доступа к Ubuntu-машине для сборки оракула

**Файлы:** нет (организационный шаг-блокер перед Задачей 4).

**Interfaces:**
- Produces: подтверждённые пользователем SSH-реквизиты Ubuntu 24.04
  (alias/host, user, способ входа) для Задачи 4.

- [ ] **Шаг 1: Спросить у пользователя доступ**

Исполнитель задаёт пользователю вопрос и ждёт ответа (имена хостов **не
угадывать**, ср. примечание в `cross-platform/README.md` «Do not guess SSH
connections»):

> «Для этапа 0 нужна однократная сборка C masscan (оракул) на физической
> Ubuntu 24.04 (решение №9 спеки studio, пользователь разрешил — §12 вопрос
> 2). Укажите, пожалуйста: SSH alias/host и пользователя Ubuntu-машины, или
> подтвердите, что соберёте оракул локально по инструкции из Задачи 4 и
> пришлёте фикстуры. Сборка и прогон `-sL`/`--echo` пакетов не отправляют.»

- [ ] **Шаг 2: Зафиксировать ответ**

Записать полученные реквизиты в черновик заметки (не в репозиторий, если в
них есть приватные адреса) и перейти к Задачам 1–3, которые от Ubuntu не
зависят. Задача 4 выполняется, когда доступ подтверждён.

---

## Задача 1: Скелет workspace `rmasscan/`

**Файлы:**
- Create: `rmasscan/Cargo.toml` (workspace)
- Create: `rmasscan/.gitignore`
- Create: `rmasscan/rust-toolchain.toml`
- Create: `rmasscan/crates/rmasscan-core/Cargo.toml`
- Create: `rmasscan/crates/rmasscan-core/src/lib.rs`
- Create: `rmasscan/crates/rmasscan-cli/Cargo.toml`
- Create: `rmasscan/crates/rmasscan-cli/src/main.rs`
- Create: `rmasscan/README.md`

**Interfaces:**
- Produces: workspace с двумя членами; `rmasscan-core` — библиотека с
  `#![forbid(unsafe_code)]` и пустым, но компилирующимся API; `rmasscan-cli`
  — бинарь, зависящий от `rmasscan-core` по `path`.

- [ ] **Шаг 1: Написать провальный тест-«дымок» в core**

`rmasscan/crates/rmasscan-core/src/lib.rs`:
```rust
#![forbid(unsafe_code)]
//! Порт ядра masscan (AGPL-3.0). Источник: masscan © Robert David Graham,
//! github.com/robertdavidgraham/masscan, HEAD 8e6b3b0.

/// Версия masscan, с которой сверяется порт.
pub const ORACLE_MASSCAN_VERSION: &str = "1.3.9-integration";

#[cfg(test)]
mod tests {
    #[test]
    fn version_constant_matches_oracle() {
        assert_eq!(super::ORACLE_MASSCAN_VERSION, "1.3.9-integration");
    }
}
```

- [ ] **Шаг 2: Написать манифесты**

`rmasscan/Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["crates/rmasscan-core", "crates/rmasscan-cli"]

[workspace.package]
edition = "2024"
publish = false
license = "AGPL-3.0-only"

[workspace.dependencies]
clap = { version = "=4.6.7", features = ["derive"] }
siphasher = "=1.0.4"
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.154"
thiserror = "=2.0.21"
proptest = "=1.12.0"
criterion = "=0.8.2"
```

`rmasscan/crates/rmasscan-core/Cargo.toml`: `name = "rmasscan-core"`,
`edition.workspace = true`, `license.workspace = true`,
`[dev-dependencies] proptest.workspace = true`. Пока без prod-зависимостей
(siphasher добавляется в этапе 1, Задача cookie).

`rmasscan/crates/rmasscan-cli/Cargo.toml`: `name = "rmasscan-cli"`,
`[[bin]] name = "rmasscan"`, зависимости `rmasscan-core = { path =
"../rmasscan-core" }`, `clap.workspace = true`.

`rmasscan/rust-toolchain.toml`: `[toolchain] channel = "1.99.1"`.

`rmasscan/.gitignore`: строки `/target/`.

- [ ] **Шаг 3: Минимальный CLI-заглушка**

`rmasscan/crates/rmasscan-cli/src/main.rs` — печатает версию и выходит 0 при
`--version`; без аргументов печатает usage в stderr и выходит 1. Реальные
опции добавляются в этапе 1.

- [ ] **Шаг 4: Прогнать сборку и тест**

Run: `cd rmasscan && cargo test`
Ожидается: PASS (1 тест), сборка без предупреждений.

- [ ] **Шаг 5: README**

`rmasscan/README.md`: назначение (порт ядра masscan, AGPL-3.0), ссылка на
спеку и этот план, команды `cargo test` / `cargo run -p rmasscan-cli --
--echo`, явное указание «raw-сокеты и сеть не используются на этапах 0–1».

- [ ] **Шаг 6 (коммит, только с согласия пользователя):**
```bash
git add rmasscan
git commit -m "chore(rmasscan): workspace skeleton for the Rust port (stage 0)"
```

---

## Задача 2: Правило «без C» — `cargo deny` и проверка графа сборки

**Файлы:**
- Create: `rmasscan/deny.toml`
- Create: `rmasscan/xtask-nocc.md` (короткая памятка команды проверки) —
  либо описать в README; файл не обязателен.
- Test: `rmasscan/tests/no_c_in_build.rs` (интеграционный тест на уровне
  workspace, в `rmasscan-core`)

**Interfaces:**
- Consumes: workspace из Задачи 1.
- Produces: `deny.toml` с бан-листом C-сборочных crates и allow-листом
  лицензий; воспроизводимые команды `cargo deny check` и
  `cargo tree -e build`, встраиваемые в CI (Задача 3).

- [ ] **Шаг 1: Написать провальный тест графа сборки**

`rmasscan/crates/rmasscan-core/tests/no_c_in_build.rs` — вызывает
`cargo tree -e build -p rmasscan-core -p rmasscan-cli` и падает, если в
выводе встречается любой из запрещённых crates:
```rust
#[test]
fn build_graph_has_no_c_toolchain_crates() {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["tree", "-e", "build", "--prefix", "none",
               "-p", "rmasscan-core", "-p", "rmasscan-cli"])
        .output()
        .expect("cargo tree runs");
    let text = String::from_utf8_lossy(&out.stdout);
    for banned in ["cc ", "cmake ", "bindgen ", "pkg-config ", "libpcap", "pcap "] {
        assert!(!text.contains(banned), "запрещённый build-crate в графе: {banned}\n{text}");
    }
}
```

- [ ] **Шаг 2: Убедиться, что тест проходит на текущем (пустом) графе**

Run: `cd rmasscan && cargo test -p rmasscan-core --test no_c_in_build`
Ожидается: PASS (зависимостей пока нет). Тест — страж на будущее: любая
новая зависимость, тянущая `cc`/`bindgen`, его уронит. (Review Focus №1.)

- [ ] **Шаг 3: Написать `deny.toml`**

`rmasscan/deny.toml` (по документации cargo-deny 0.20.2; targets — три
целевые ОС):
```toml
[graph]
targets = [
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
]
all-features = true

[bans]
multiple-versions = "warn"
wildcards = "deny"
deny = [
    { crate = "cc", reason = "компилирует C в сборке (спека §6.1)" },
    { crate = "cmake", reason = "вызывает C/C++ тулчейн" },
    { crate = "bindgen", reason = "генерация во время сборки через libclang" },
    { crate = "pkg-config", reason = "линковка системных C-библиотек" },
    { crate = "pcap", reason = "линкует libpcap (спека §5.2, отклонён)" },
    { crate = "libpnet", reason = "Windows-бэкенд линкует Packet.lib (спека §5.2)" },
    { crate = "openssl", use-instead = "нет TLS-крипто в v1 (спека §6.2)" },
    { crate = "openssl-sys" },
    { crate = "ring", reason = "C/asm крипто не нужны (спека §6.2)" },
    { crate = "aws-lc-rs", reason = "C/asm крипто не нужны (спека §6.2)" },
    { crate = "libfuzzer-sys", reason = "libFuzzer C++; fuzzing не на этапах 0–1 (спека §12 вопрос 3)" },
]

[licenses]
confidence-threshold = 0.93
allow = ["Apache-2.0", "MIT", "Unicode-3.0", "ISC", "BSD-3-Clause", "Zlib", "AGPL-3.0-only"]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

Примечание: наши crates — `AGPL-3.0-only`, он в allow-листе; зависимости —
MIT/Apache/Unicode (siphasher, clap, serde, thiserror — проверить при
первом `cargo deny check licenses` на этапе 1).

- [ ] **Шаг 4: Прогнать cargo deny**

Run: `cd rmasscan && cargo install --locked cargo-deny@0.20.2 && cargo deny check bans licenses sources`
Ожидается: `advisories/bans/licenses/sources ok` (граф почти пуст).
Зафиксировать точную команду в README для CI.

- [ ] **Шаг 5 (коммит, только с согласия пользователя):**
```bash
git add rmasscan/deny.toml rmasscan/crates/rmasscan-core/tests/no_c_in_build.rs rmasscan/README.md
git commit -m "chore(rmasscan): enforce no-C build graph via cargo-deny and cargo tree"
```

---

## Задача 3: CI на трёх ОС без raw-сокетов

**Файлы:**
- Create: `.github/workflows/rmasscan.yml` (в корне репозитория studio)

**Interfaces:**
- Consumes: Задачи 1 и 2 (`cargo test`, `cargo deny`, `cargo tree -e build`).
- Produces: зелёный CI на `ubuntu-24.04`, `macos-14`, `windows-2022`,
  запускающий fmt, clippy, test, проверку «без C».

- [ ] **Шаг 1: Написать workflow**

`.github/workflows/rmasscan.yml`: матрица
`os: [ubuntu-24.04, macos-14, windows-2022]`, `defaults.run.working-directory:
rmasscan`. Шаги: checkout; установка toolchain 1.99.1 с `rustfmt`, `clippy`;
кеш cargo; `cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`;
`cargo test --all`; установка `cargo-deny@0.20.2` (`cargo install --locked`);
`cargo deny check bans licenses sources`. Проверка «без C» выполняется самим
тестом `no_c_in_build` (Задача 2), поэтому отдельного шелл-шага не нужно —
это держит проверку одинаковой на трёх ОС (Review Focus №2). Raw-сокеты,
сеть, повышение прав не используются.

- [ ] **Шаг 2: Проверить синтаксис локально**

Run: `cd rmasscan && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --all`
Ожидается: всё PASS локально на macOS (три-ОС-прогон подтверждается в CI
после push).

- [ ] **Шаг 3 (коммит/пуш, только с согласия пользователя):**
```bash
git add .github/workflows/rmasscan.yml
git commit -m "ci(rmasscan): build, lint, test and no-C check on three OSes"
```
После push — проверить, что три джоба зелёные (критерий выхода этапа 0).

---

## Задача 4: Сборка C-оракула и golden-фикстуры `-sL`/`--echo`

**Выполняется на Ubuntu-машине из Задачи 0 (или локально пользователем).
Пакеты в сеть не отправляются.**

**Файлы:**
- Create: `rmasscan/tests/golden/manifest.json`
- Create: `rmasscan/tests/golden/listscan/*.txt` (вывод `-sL`)
- Create: `rmasscan/tests/golden/echo/*.conf` (вывод `--echo`)
- Create: `rmasscan/tests/golden/paused/*.conf` (снятые `paused.conf`-образцы для §7.2 п4)
- Create: `rmasscan/tests/golden/README.md` (как воспроизвести)
- Create: `rmasscan/scripts/build-oracle.sh` (скрипт сборки и захвата)

**Interfaces:**
- Consumes: SSH-доступ из Задачи 0.
- Produces: офлайн-фикстуры и `manifest.json`, по которым тесты этапа 1
  (differential §7.2 п1, п3, п4) сверяются без C-бинарника.

- [ ] **Шаг 1: Скрипт сборки оракула**

`rmasscan/scripts/build-oracle.sh` (bash, запускается на Ubuntu 24.04):
1. `git clone https://github.com/robertdavidgraham/masscan && cd masscan &&
   git checkout 8e6b3b0`; проверить `test "$(git rev-parse HEAD)" =
   8e6b3b0c07a81e8ea61d557c06134a21a6881614` иначе выход с ошибкой (Review
   Focus №4).
2. `make -j` (компилятор C — на оракул-машине, не в нашем продукте и не в
   CI; спека §6.3 это разрешает как разовую сборку эталона).
3. Записать `sha256sum bin/masscan` и `bin/masscan --version` в манифест.

- [ ] **Шаг 2: Матрица `-sL` (спека §7.2 п1)**

Для каждой строки матрицы запустить `bin/masscan -sL <args>` и сохранить
stdout в `tests/golden/listscan/<case>.txt`. Матрица (все с явным `--seed`,
`--blackrock-rounds 14` по умолчанию):
- одиночные и диапазоны целей: `10.0.0.0/30 -p80`, `10.0.0.0/24 -p80,443`,
  `192.168.0.0/22 -p0-1023`, крупный `10.0.0.0/8 -p80 --exclude 10.0.0.0/9`
  (исключение режет диапазон, Review Focus №3);
- `--seed 1`, `--seed 2`, `--seed 4294967295`;
- shard `1/1`, `2/3`;
- `--resume-index 100 --resume-count 50`;
- `--retries 0` и `--retries 2` (помня `end += retries * max_rate`,
  main-listscan.c:35).
Каждый случай — отдельный файл; имя файла кодирует аргументы.

- [ ] **Шаг 3: Матрица `--echo` (спека §7.2 п3)**

Для представительного набора конфигураций запустить `bin/masscan --echo
<args>` и `--echo-all`, сохранить в `tests/golden/echo/<case>.conf`. Включить
支持ные опции §7.1: `--seed`, `--rate`, `-p/--ports`, цели/`--range`,
`--exclude`, `--retries`, `--shard`, `--adapter-ip`, `--adapter-mac`,
`--router-mac`, `--source-port`, `--blackrock-rounds`, `--wait`.

- [ ] **Шаг 4: Образцы `paused.conf` (спека §7.2 п4)**

Снять 2–3 реальных `paused.conf` (прервав `bin/masscan --offline` по
Ctrl-C в namespace без сети, либо `masscan_save_state` эквивалент) и положить
в `tests/golden/paused/`. Это офлайн-операция.

- [ ] **Шаг 5: Манифест**

`tests/golden/manifest.json` (сериализуется/читается `serde_json` в тесте
этапа 1):
```json
{
  "masscan_git_head": "8e6b3b0c07a81e8ea61d557c06134a21a6881614",
  "masscan_version": "1.3.9-integration",
  "binary_sha256": "<из шага 1>",
  "built_on": "Ubuntu 24.04",
  "built_at": "<ISO-дата>",
  "cases": [
    { "file": "listscan/slash30_p80_seed1.txt", "mode": "-sL",
      "args": ["-sL", "10.0.0.0/30", "-p80", "--seed", "1"] }
  ]
}
```
Каждому фикстур-файлу соответствует запись с точной командой (Review Focus
№3 инфраструктурный аспект).

- [ ] **Шаг 6: Офлайн-бенчмарк C для порога ≥80% (спека §9 этап 1, §7.6)**

На оракул-машине один раз: `bin/masscan 0.0.0.0/4 -p80 --rate 100000000
--offline` с замером времени/скорости генерации; записать достигнутый
pps-оракула в `manifest.json` (`"offline_gen_pps": <N>`). Этап 1, задача
бенчмарка сверяется с этим числом.

- [ ] **Шаг 7: Перенести фикстуры в репозиторий и зафиксировать**

Скопировать `tests/golden/**` и `manifest.json` в
`/Users/denyskolomiiets/masscan-studio/rmasscan/tests/golden/`.
`tests/golden/README.md` описывает воспроизведение (скрипт, HEAD, namespace).

- [ ] **Шаг 8 (коммит, только с согласия пользователя):**
```bash
git add rmasscan/tests/golden rmasscan/scripts/build-oracle.sh
git commit -m "test(rmasscan): golden -sL/--echo fixtures from pinned C oracle 8e6b3b0"
```

---

## Критерий выхода этапа 0

- CI (`.github/workflows/rmasscan.yml`) зелёный на Ubuntu 24.04, macOS 14,
  Windows (Задача 3).
- `cargo tree -e build` над `rmasscan-core`/`rmasscan-cli` не содержит
  C-сборочных crates; тест `no_c_in_build` и `cargo deny check` проходят
  (Задачи 2, 3).
- Golden-фикстуры `-sL`/`--echo`/`paused.conf` и `manifest.json` с хэшем
  бинарника и версией лежат в `rmasscan/tests/golden/` (Задача 4).

## Самопроверка плана (этап 0)

- Покрытие §9 «этап 0»: подготовка workspace (Задача 1), `cargo deny` без C
  (Задача 2), CI на трёх ОС без raw-сокетов (Задача 3), сборка оракула +
  фикстуры + фиксация хэша (Задача 4). Все пункты строки «0. Подготовка»
  закрыты.
- Решение автора (отдельный workspace) обосновано контаминацией
  `cross-platform/Cargo.lock` C-сборочными crates.
- Версии зафиксированы и совместимы с edition 2024 / rustc 1.99.1
  (подтверждено локально и по crates.io).
- Шаг запроса доступа к Ubuntu стоит первым (Задача 0), хосты не угадываются.
