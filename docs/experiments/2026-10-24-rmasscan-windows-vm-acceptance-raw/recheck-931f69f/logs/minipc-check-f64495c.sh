#!/bin/bash
set -u
. "$HOME/.cargo/env"
D="$HOME/rmasscan-check/f64495c"
rm -rf "$D" && mkdir -p "$D" && tar -xf "$HOME/rmasscan-check/f64495c.tar" -C "$D" && rm -f "$HOME/rmasscan-check/f64495c.tar"
cd "$D" && git init -q && git add -A
echo "== guard"; bash scripts/language-guard.sh; echo "guard rc=$?"
grep --version | head -1
cd rmasscan
export CARGO_TARGET_DIR="$HOME/rmasscan-check/target"
echo "== clippy"; cargo clippy --locked --workspace --all-targets -- -D warnings 2>&1 | tail -4; echo "clippy rc=${PIPESTATUS[0]}"
echo "== test"; cargo test --locked --workspace --no-fail-fast 2>&1 | grep -E '^test result|FAILED|panicked|^error'; echo "test rc=${PIPESTATUS[0]}"
echo "== deny"; if command -v cargo-deny >/dev/null; then cargo deny check bans licenses sources 2>&1 | tail -2; echo "deny rc=${PIPESTATUS[0]}"; else echo "cargo-deny not installed: NOT RUN"; fi
