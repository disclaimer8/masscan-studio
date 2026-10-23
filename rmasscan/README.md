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

## Ограничения

Raw-сокеты и сеть не используются на этапах 0–1. Повышенные привилегии не
нужны.
