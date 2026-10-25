#!/usr/bin/env bash
# Build the pinned C masscan oracle and capture golden fixtures for rmasscan.
# Runs on the oracle host (Ubuntu x86_64, gcc, make, git, sudo).
# Re-runnable. Work dir: ~/rmasscan-oracle (override with ORACLE_DIR).
#
# SAFETY: every masscan invocation runs inside a fresh network namespace
# (`sudo unshare -n`, only a DOWN loopback exists), so no packet can leave.
# `unshare -rn` (user namespace) is preferred but Ubuntu 24.04+ AppArmor blocks
# unprivileged user namespaces, so we fall back to root + network namespace.
# Non -sL/--echo runs always pass --offline.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAB_BIN="${RMASSCAN_LAB_BIN:-$HERE/../target/release/rmasscan-lab}"
[ -x "$LAB_BIN" ] || { echo "Build rmasscan-lab or set RMASSCAN_LAB_BIN" >&2; exit 2; }

PIN=8e6b3b0c07a81e8ea61d557c06134a21a6881614
ORACLE_DIR="${ORACLE_DIR:-$HOME/rmasscan-oracle}"
SRC="$ORACLE_DIR/masscan"
OUT="$ORACLE_DIR/golden"
BIN="$SRC/bin/masscan"
MAX_FULL=$((1024*1024))   # commit full output only if <= 1 MiB
HEAD_LINES=2000
mkdir -p "$ORACLE_DIR"

# ---- network isolation -----------------------------------------------------
if unshare -rn true 2>/dev/null; then
  NS=(unshare -rn); NS_KIND="unshare -rn"
elif sudo -n unshare -n true 2>/dev/null; then
  NS=(sudo -n unshare -n); NS_KIND="sudo unshare -n"
else
  echo "FATAL: cannot create a network namespace; refusing to run masscan" >&2; exit 2
fi
# Assert the namespace really has no usable network (non-vacuous: needs `ip`,
# the command must succeed, and the list must be non-empty and contain only lo).
command -v ip >/dev/null || { echo "FATAL: 'ip' not found; cannot verify isolation" >&2; exit 2; }
ns_links=$("${NS[@]}" ip -o link) || { echo "FATAL: 'ip -o link' failed inside namespace" >&2; exit 2; }
[ -n "$ns_links" ] || { echo "FATAL: namespace interface list is empty" >&2; exit 2; }
echo "$ns_links" | grep -q ': lo:' || { echo "FATAL: namespace has no lo" >&2; exit 2; }
[ "$(echo "$ns_links" | grep -vc ': lo:' || true)" = "0" ] || { echo "FATAL: namespace has interfaces besides lo" >&2; exit 2; }
echo "[*] isolation: $NS_KIND"

# masscan reads /etc/masscan/masscan.conf before argv (main.c ~1627) for every operation.
# Checked inside the namespace wrapper because masscan runs as root there.
if "${NS[@]}" test -e /etc/masscan/masscan.conf; then
  echo "FATAL: /etc/masscan/masscan.conf exists; it would silently alter every fixture" >&2; exit 2
fi

# ---- clone / verify / build ------------------------------------------------
if [ ! -d "$SRC/.git" ]; then
  git clone https://github.com/robertdavidgraham/masscan "$SRC"
fi
git -C "$SRC" fetch -q origin || true
git -C "$SRC" checkout -q "$PIN"
[ "$(git -C "$SRC" rev-parse HEAD)" = "$PIN" ] || { echo "FATAL: HEAD != $PIN" >&2; exit 1; }
# The Makefile compiles $(wildcard src/*.c), so untracked files would enter the build.
[ -z "$(git -C "$SRC" status --porcelain --untracked-files=all)" ] || { echo "FATAL: masscan tree not clean (modified or untracked files)" >&2; exit 1; }
make -C "$SRC" -j4 >"$ORACLE_DIR/make.log" 2>&1 || { tail -30 "$ORACLE_DIR/make.log"; exit 1; }
BIN_SHA=$(sha256sum "$BIN" | cut -d' ' -f1)
VERSION=$("${NS[@]}" "$BIN" --version 2>&1 | grep -i 'version' | head -1 | sed 's/^Masscan version //; s/ *(.*$//' || true)
[ -n "$VERSION" ] || { echo "FATAL: empty version string from --version" >&2; exit 1; }
echo "[*] binary sha256 $BIN_SHA ; $VERSION"

# ---- offline-capable build -------------------------------------------------
# Upstream finding: on Linux, `--offline` leaves adapter->link_type = 0 (DLT_NULL);
# the IPv6 template then writes AF_INET6 (10 on Linux) but preprocess_frame()
# only accepts 24/28/30 (BSD/macOS values) => "FAILED: bad packet template",
# so `--offline` cannot start at the pinned commit on Linux. For the paused.conf
# captures and the offline benchmark ONLY, we build a copy with a one-line patch
# (offline adapter reports DLT_EN10MB). -sL/--echo use the unpatched pinned binary.
SRC_OFF="$ORACLE_DIR/masscan-offline"
rm -rf "$SRC_OFF"; mkdir -p "$SRC_OFF"
git -C "$SRC" archive "$PIN" | tar -x -C "$SRC_OFF"
"$LAB_BIN" oracle-util patch-offline "$SRC_OFF/src/rawsock.c"
make -C "$SRC_OFF" -j4 >"$ORACLE_DIR/make-offline.log" 2>&1 || { tail -30 "$ORACLE_DIR/make-offline.log"; exit 1; }
BIN_OFF="$SRC_OFF/bin/masscan"
BIN_OFF_SHA=$(sha256sum "$BIN_OFF" | cut -d' ' -f1)
echo "[*] offline-patched binary sha256 $BIN_OFF_SHA"

rm -rf "$OUT"; mkdir -p "$OUT/listscan" "$OUT/echo" "$OUT/paused"
CASES="$OUT/.cases.jsonl"; : >"$CASES"

# rec FILE MODE EXTRA_JSON ARGS... : emit one JSON manifest record (args = exact masscan arguments)
rec() { "$LAB_BIN" oracle-util record "$@"; }

# run_capture DIR NAME EXT MODE ARGS... : run masscan twice under ns, compare, store stdout (or head if > 1 MiB)
run_capture() {  # $1=dir $2=case $3=ext $4=mode ; rest = args
  local dir=$1 name=$2 ext=$3 mode=$4; shift 4
  local full="$OUT/$dir/$name.full.tmp" full2="$OUT/$dir/$name.full2.tmp"
  "${NS[@]}" "$BIN" "$@" >"$full" 2>/dev/null
  "${NS[@]}" "$BIN" "$@" >"$full2" 2>/dev/null
  local s1 s2; s1=$(sha256sum <"$full"|cut -d' ' -f1); s2=$(sha256sum <"$full2"|cut -d' ' -f1)
  [ "$s1" = "$s2" ] || { echo "FATAL: nondeterministic output for $name" >&2; exit 3; }
  rm -f "$full2"
  local lines size; lines=$(wc -l <"$full"); size=$(stat -c %s "$full")
  local rel trunc
  if [ "$size" -le "$MAX_FULL" ]; then
    rel="$dir/$name.$ext"; mv "$full" "$OUT/$rel"; trunc=false
  else
    rel="$dir/$name.head.$ext"; head -n "$HEAD_LINES" "$full" >"$OUT/$rel"; rm -f "$full"; trunc=true
  fi
  rec "$rel" "$mode" "{\"line_count\":$lines,\"sha256\":\"$s1\",\"truncated\":$trunc,\"size_bytes\":$size,\"deterministic\":true,\"binary\":\"pinned\"}" "$@" >>"$CASES"
  echo "[+] $rel lines=$lines bytes=$size truncated=$trunc"
}

# ---- -sL matrix ------------------------------------------------------------
sL() { local name=$1; shift; run_capture listscan "$name" txt "-sL" -sL "$@"; }
sL slash30_p80_seed1        10.0.0.0/30 -p80 --seed 1
sL slash24_p80-443_seed1    10.0.0.0/24 -p80,443 --seed 1
sL slash22_p0-1023_seed1    192.168.0.0/22 -p0-1023 --seed 1
sL slash8_excl_slash9_p80_seed1 10.0.0.0/8 -p80 --exclude 10.0.0.0/9 --seed 1
sL slash24_p80_seed1        10.0.0.0/24 -p80 --seed 1
sL slash24_p80_seed2        10.0.0.0/24 -p80 --seed 2
sL slash24_p80_seed4294967295 10.0.0.0/24 -p80 --seed 4294967295
sL slash24_p80_seed1_rounds14 10.0.0.0/24 -p80 --seed 1 --blackrock-rounds 14
sL slash24_p80_seed1_rounds4  10.0.0.0/24 -p80 --seed 1 --blackrock-rounds 4
sL slash24_p80_seed1_shard1of1 10.0.0.0/24 -p80 --seed 1 --shard 1/1
sL slash24_p80_seed1_shard2of3 10.0.0.0/24 -p80 --seed 1 --shard 2/3
sL slash24_p80_seed1_resume100_count50 10.0.0.0/24 -p80 --seed 1 --resume-index 100 --resume-count 50
sL slash24_p80_seed1_retries0 10.0.0.0/24 -p80 --seed 1 --retries 0
sL slash24_p80_seed1_retries2 10.0.0.0/24 -p80 --seed 1 --retries 2
sL slash24_p80_seed1_retries2_rate1000 10.0.0.0/24 -p80 --seed 1 --retries 2 --rate 1000
sL multirange_ports_seed7   10.0.0.0/30,172.16.5.0-172.16.5.9 -p22,80,443,8000-8003 --seed 7
sL exclude_list_seed3       10.1.0.0/28 -p80,443 --exclude 10.1.0.4/30 --seed 3
sL ipv6_slash126_p80_seed1  2001:db8::/126 -p80 --seed 1
# edge cases: blackrock_init special-cases ranges 0-8 (table at crypto-blackrock.c:116-148)
sL single_ip_p80_seed1      10.0.0.1 -p80 --seed 1
sL slash31_p80_seed1        10.0.0.0/31 -p80 --seed 1
sL range3_p80_seed1         10.0.0.0-10.0.0.2 -p80 --seed 1
sL slash30_allports_seed1   10.0.0.0/30 -p0-65535 --seed 1
sL ipv6_slash126_p80-443_seed1 2001:db8::/126 -p80,443 --seed 1

# ---- --echo matrix ---------------------------------------------------------
# NOTE: without --seed, masscan picks a random seed and --echo prints it, so every case pins --seed.
ec() { local name=$1; shift
  run_capture echo "$name" conf "--echo" --echo "$@"
  run_capture echo "$name.all" conf "--echo-all" --echo-all "$@"; }
ec minimal_p80                10.0.0.0/30 -p80 --seed 1
ec seed_rate_retries          10.0.0.0/24 -p80,443 --seed 12345 --rate 5000 --retries 3
ec ranges_exclude             --range 10.0.0.0/24 --range 192.168.1.0-192.168.1.20 -p0-100 --exclude 10.0.0.128/25 --seed 5
ec shard_rounds               10.0.0.0/24 -p80 --shard 2/3 --blackrock-rounds 7 --seed 9
ec adapter_opts               10.0.0.0/24 -p80 --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --router-mac 66-55-44-33-22-11 --source-port 40000 --seed 6
ec wait_and_ports             10.0.0.0/30 --ports 22,80,443,8080-8090 --wait 5 --seed 4294967295
ec everything                 10.0.0.0/22 -p1-1024 --exclude 10.0.1.0/24 --seed 77 --rate 250000 --retries 1 --shard 1/2 --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --router-mac 66-55-44-33-22-11 --source-port 50000 --blackrock-rounds 14 --wait 3
# begin==0 ranges hit UB in range_first_cidr (massip-rangesv4.c:98-124); gcc x86-64 prints them dashed
# (or as /4294967295 for 0.0.0.0/31). --echo only: the .all form is identical (main.c:1803-1805).
run_capture echo zero_slash4  conf "--echo" --echo 0.0.0.0/4  -p80 --seed 1
run_capture echo zero_slash31 conf "--echo" --echo 0.0.0.0/31 -p80 --seed 1

# ---- paused.conf captures (offline, SIGINT after 2s; outer SIGKILL guard after 40s: `timeout -k` kills masscan before it saves) -------------------------
ADAPT=(--interface lo --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 --router-mac 66-55-44-33-22-11 --source-port 40000)
paused() { local name=$1; shift
  local d; d=$(mktemp -d "$ORACLE_DIR/paused.XXXXXX")
  # shellcheck disable=SC2016
  "${NS[@]}" bash -c 'cd "$1"; shift; timeout -s KILL 40 timeout -s INT 2 "$@" >/dev/null 2>&1 || true' _ "$d" "$BIN_OFF" "$@" --offline "${ADAPT[@]}" --rate 1000 --wait 0
  [ "$(id -u)" = 0 ] || sudo -n chown -R "$(id -u):$(id -g)" "$d" 2>/dev/null || true
  sudo -n pkill -KILL -x masscan 2>/dev/null || true   # leftover from the KILL guard
  [ -f "$d/paused.conf" ] || { echo "FATAL: no paused.conf for $name" >&2; exit 4; }
  cp "$d/paused.conf" "$OUT/paused/$name.conf"; rm -rf "$d"
  local sha; sha=$(sha256sum <"$OUT/paused/$name.conf"|cut -d' ' -f1)
  rec "paused/$name.conf" paused "{\"sha256\":\"$sha\",\"line_count\":$(wc -l <"$OUT/paused/$name.conf"),\"truncated\":false,\"note\":\"resume index is time dependent (SIGINT after ~2s at --rate 1000); parse-compare, do not hash-compare\",\"signal\":\"timeout -s KILL 40 timeout -s INT 2\",\"binary\":\"offline-patched\"}" "$@" --offline "${ADAPT[@]}" --rate 1000 --wait 0 >>"$CASES"
  echo "[+] paused/$name.conf"; }
paused seed1_p80_slash16       10.0.0.0/16 -p80 --seed 1
paused seed424242_multi        192.168.0.0/20 -p22,80,443 --seed 424242 --retries 2
paused seed9_resume_index      172.16.0.0/16 -p0-9 --seed 9 --resume-index 5000
# the flags studio always passes: C then also writes `output-format = interactive`
paused studio_flags            192.168.0.0/16 -p80 --seed 3 --interactive --output-format interactive -e lo

# ---- offline benchmark -----------------------------------------------------
BENCH_ARGS=(0.0.0.0/4 -p80 --rate 100000000 --offline "${ADAPT[@]}" --seed 1 --wait 0)
BENCH_TOTAL=$((1<<28))
tm="$ORACLE_DIR/bench.time"
BENCH_CMD=("${NS[@]}" /usr/bin/time -v -o "$tm" timeout 120 "$BIN_OFF" "${BENCH_ARGS[@]}")
if ! "${BENCH_CMD[@]}" >/dev/null 2>"$ORACLE_DIR/bench.stderr"; then
  echo "FATAL: benchmark failed/timed out (>120s); reduce range" >&2; tail -5 "$ORACLE_DIR/bench.stderr"; exit 5
fi
WALL=$(awk -F': ' '/Elapsed \(wall clock\)/{print $NF}' "$tm")
CPU_MODEL=$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)

# ---- manifest --------------------------------------------------------------
BIN_OFF_SHA="$BIN_OFF_SHA" "$LAB_BIN" oracle-util manifest "$OUT" "$PIN" "$VERSION" "$BIN_SHA" "$NS_KIND" "$WALL" "$BENCH_TOTAL" "$CPU_MODEL" "$(printf '%q ' "${BENCH_CMD[@]}")"
rm -f "$CASES"
"$LAB_BIN" oracle-util validate-json "$OUT/manifest.json" >/dev/null
echo "[*] done: $OUT"
