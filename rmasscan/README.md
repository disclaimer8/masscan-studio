# rmasscan

Порт ядра сканера [masscan](https://github.com/robertdavidgraham/masscan) на
чистый Rust. Лицензия: AGPL-3.0-only. Оригинал © Robert David Graham; сверка
ведётся с HEAD `8e6b3b0` (версия `1.3.9-integration`).

Документы:

- спека: `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`
- планы этапов 0–1: `docs/superpowers/plans/`

## Команды

```bash
cd rmasscan
cargo test
cargo run -p rmasscan-cli -- --echo
```

На этапе 0 CLI является заглушкой: поддерживается только `--version`. Опция
`--echo` появится на этапе 1.

## Проверка «без C в сборке»

Граф сборки не должен содержать C-тулчейн (`cc`, `cmake`, `bindgen`,
`pkg-config`, libpcap). Проверяют два механизма: интеграционный тест
`crates/rmasscan-core/tests/no_c_in_build.rs` (`cargo tree -e normal,build`) и
`cargo deny`. Точные команды для CI:

```bash
cargo install --locked cargo-deny@0.20.2
cargo deny check bans licenses sources
cargo test -p rmasscan-core --test no_c_in_build
```

## Ограничения

Raw-сокеты и сеть не используются на этапах 0–1. Повышенные привилегии не
нужны.
