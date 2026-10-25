#!/bin/bash
set -u
cd "$1/rmasscan"
export CARGO_TARGET_DIR="$2"
echo "== commit $(git rev-parse HEAD) dirty=$(git status --porcelain | wc -l | tr -d ' ')"
uname -sm; rustc --version
echo "== fmt"; cargo fmt --all --check; echo "fmt rc=$?"
echo "== clippy"; cargo clippy --locked --workspace --all-targets -- -D warnings 2>&1 | tail -3; echo "clippy rc=${PIPESTATUS[0]}"
echo "== test"; cargo test --locked --workspace 2>&1 | grep -E '^test result|FAILED|panicked|Running'; echo "test rc=${PIPESTATUS[0]}"
echo "== deny"; cargo deny check bans licenses sources 2>&1 | tail -2; echo "deny rc=${PIPESTATUS[0]}"
echo "== guard"; (cd .. && bash scripts/language-guard.sh); echo "guard rc=$?"
