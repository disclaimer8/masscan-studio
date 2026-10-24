# masscan-studio

A Rust-only repository. It holds a pure-Rust port of the
[masscan](https://github.com/robertdavidgraham/masscan) scanner core (`rmasscan/`),
its laboratory and acceptance tooling, and the design record. A Rust/Slint desktop
studio is planned as future work; nothing of it exists yet.

The Swift v0.3 macOS app was retired on 2026-10-24. It lives in git history; the last
commit that contains it is `5b2f88bc949d6cdfa1a75d7122074aa22581d513`
(`git checkout 5b2f88b -- Sources Tests Package.swift` restores it).

## Layout

| Path | Content |
| --- | --- |
| `rmasscan/` | Cargo workspace: `rmasscan-core`, `rmasscan-engine`, `rmasscan-net`, `rmasscan-cli`, `rmasscan-lab` |
| `rmasscan/README.md` | The port: commands, deliberate differences from masscan, the no-C-in-build check |
| `rmasscan/docs/rust-lab.md` | Rust laboratory tools (evidence verifier, packet comparator, suites) |
| `rmasscan/docs/windows-vm-lab.md`, `rmasscan/docs/windows-wire-lab.md` | Windows VM and wire-parity labs |
| `rmasscan/BENCHMARKS.md` | Speed measurements |
| `docs/experiments/` | Dated experiment and acceptance records |
| `docs/superpowers/` | Historical plans and design specs (kept as written) |
| `docs/history/` | Retired documents, for example the Swift app's verification notes |
| `scripts/language-guard.sh` | Repository language policy (see below) |

## Build and test

```sh
cd rmasscan
cargo build --locked --release
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
```

The toolchain is pinned by `rmasscan/rust-toolchain.toml`. The build graph must not
contain a C toolchain; `crates/rmasscan-core/tests/no_c_in_build.rs` and `cargo deny`
check it.

## Language policy

Tracked source files are Rust, plus thin shell and PowerShell wrappers. Swift, Python,
C, C++ and Objective-C sources are not allowed. `bash scripts/language-guard.sh`
enforces it (CI workflow `language-guard.yml`, no path filter), and
`rmasscan/crates/rmasscan-lab/tests/rust_only.rs` is the same policy as a Rust test.

## Licence

`rmasscan/` is AGPL-3.0-only; masscan is copyright Robert David Graham. See
`rmasscan/LICENSE` and `rmasscan/NOTICE`.
