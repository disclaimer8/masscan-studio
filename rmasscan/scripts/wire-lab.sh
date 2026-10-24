#!/usr/bin/env bash
# Sealed Linux wire lab: runs the ORIGINAL pinned C masscan between two network
# namespaces joined by a veth pair and records the peer-side wire as classic pcap.
#
#   wire-lab.sh --oracle /path/to/masscan --out DIR                       # C oracle capture (default suite)
#   wire-lab.sh --oracle BIN --out DIR --suite rust --rust-bin WIRE_SCAN --fixtures tests/golden/wire
#   wire-lab.sh --oracle BIN --out DIR --suite perf --rust-bin WIRE_SCAN [--reps 5] [--rates 100,1000,10000,100000]
#
# Suites rust/perf run rmasscan-lab wire-suite inside the same sealed lab (same seal assertions,
# same cleanup); `rust` ends by deleting the veth on purpose, so it is the last thing it does.
#
# SEALED: no uplink, no bridge, no NAT, no default route, ip_forward=0, IPv6 off.
# The veth pair is created INSIDE the scanner namespace (peer moved straight
# into the second one), so no lab link ever exists in the host namespace.
# CLEANUP touches only this run's own namespaces, child PIDs and files:
# no pkill/killall, no firewall/route/bridge changes, no edits to host files.
# Needs root (re-execs itself through `sudo -n`). Linux only.
set -euo pipefail
# Byte-order sorting everywhere: `capture isolation` compares the host link baseline against a
# byte-sorted list, and a locale collation (en_US.UTF-8) orders br0 / br-1a2b differently.
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/lab-process-group.sh"
LAB_BIN="${RMASSCAN_LAB_BIN:-$HERE/../target/release/rmasscan-lab}"
[ -x "$LAB_BIN" ] || { echo "Build rmasscan-lab or set RMASSCAN_LAB_BIN" >&2; exit 2; }
ORACLE=""; OUT=""; SUITE=oracle; RUST_BIN=""; FIXTURES=""; REPS=5; RATES=100,1000,10000,100000
while [ $# -gt 0 ]; do
  case "$1" in
    --oracle) ORACLE=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --suite) SUITE=$2; shift 2 ;;
    --rust-bin) RUST_BIN=$2; shift 2 ;;
    --fixtures) FIXTURES=$2; shift 2 ;;
    --reps) REPS=$2; shift 2 ;;
    --rates) RATES=$2; shift 2 ;;
    -h|--help) sed -n 2,16p "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
[ -n "$ORACLE" ] && [ -n "$OUT" ] || { echo "usage: wire-lab.sh --oracle BIN --out DIR" >&2; exit 64; }
case "$SUITE" in oracle) ;; rust|perf) [ -n "$RUST_BIN" ] || { echo "--suite $SUITE needs --rust-bin" >&2; exit 64; } ;; *) echo "unknown suite: $SUITE" >&2; exit 64 ;; esac
[ "$SUITE" != rust ] || [ -n "$FIXTURES" ] || { echo "--suite rust needs --fixtures" >&2; exit 64; }
[ "$(uname -s)" = Linux ] || { echo "FATAL: Linux only" >&2; exit 2; }
if [ "$(id -u)" != 0 ]; then
  mkdir -p "$OUT"
  REEXEC=(--oracle "$(readlink -f "$ORACLE")" --out "$(readlink -f "$OUT")" --suite "$SUITE" --reps "$REPS" --rates "$RATES")
  [ -z "$RUST_BIN" ] || REEXEC+=(--rust-bin "$(readlink -f "$RUST_BIN")")
  [ -z "$FIXTURES" ] || REEXEC+=(--fixtures "$(readlink -f "$FIXTURES")")
  exec sudo -n env "RMASSCAN_LAB_BIN=$LAB_BIN" "WIRELAB_INJECT=${WIRELAB_INJECT:-}" \
    ${RMASSCAN_DEPLOY_MANIFEST:+"RMASSCAN_DEPLOY_MANIFEST=$(readlink -f "$RMASSCAN_DEPLOY_MANIFEST")"} \
    ${WIRELAB_MAC_A+"WIRELAB_MAC_A=$WIRELAB_MAC_A"} ${WIRELAB_MAC_B+"WIRELAB_MAC_B=$WIRELAB_MAC_B"} \
    ${WIRELAB_IP_A_LINK+"WIRELAB_IP_A_LINK=$WIRELAB_IP_A_LINK"} ${WIRELAB_IP_ADAPTER+"WIRELAB_IP_ADAPTER=$WIRELAB_IP_ADAPTER"} \
    ${WIRELAB_PEER_IPS+"WIRELAB_PEER_IPS=$WIRELAB_PEER_IPS"} ${WIRELAB_PEER_PREFIX+"WIRELAB_PEER_PREFIX=$WIRELAB_PEER_PREFIX"} \
    ${WIRELAB_OPEN_PORTS+"WIRELAB_OPEN_PORTS=$WIRELAB_OPEN_PORTS"} ${WIRELAB_CASES_FILE+"WIRELAB_CASES_FILE=$WIRELAB_CASES_FILE"} \
    "$0" "${REEXEC[@]}"
fi
[ -x "$ORACLE" ] || { echo "FATAL: oracle not executable: $ORACLE" >&2; exit 2; }
for t in ip timeout unshare setsid tcpdump; do command -v "$t" >/dev/null || { echo "FATAL: missing $t (the capture witness is tcpdump)" >&2; exit 2; }; done
if [ "$SUITE" = perf ]; then
  [ -x /usr/bin/time ] && /usr/bin/time -v -o /dev/null true >/dev/null 2>&1 || { echo "FATAL: the perf suite needs GNU time at /usr/bin/time (apt install time)" >&2; exit 2; }
fi

# ---- binding (explicit; identical for every case) ----------------------------
RUN_ID="$$-$RANDOM"
NS_A="wl-scan-$RUN_ID"; NS_B="wl-peer-$RUN_ID"
IF_A=veth-a; IF_B=veth-b
# The defaults are the Linux binding. The Windows stand overrides them (same script, same capture path) with
# WIRELAB_* so that the C oracle fixtures use the SAME source IP/MAC and peer MAC as the real Windows run.
MAC_A=${WIRELAB_MAC_A:-02:aa:00:00:00:01}; MAC_B=${WIRELAB_MAC_B:-02:aa:00:00:00:02}
IP_A_LINK=${WIRELAB_IP_A_LINK-10.200.0.1}             # empty = no address on the scanner end
IP_ADAPTER=${WIRELAB_IP_ADAPTER:-10.200.0.100}         # adapter IP is NOT assigned to any interface
PEER_IPS=${WIRELAB_PEER_IPS:-"10.200.0.2 10.200.0.3 10.200.0.4 10.200.0.5"}
PEER_PREFIX=${WIRELAB_PEER_PREFIX:-24}
OPEN_PORTS=${WIRELAB_OPEN_PORTS:-80,8080}               # responder listens here; every other port gets RST
CASES_FILE=${WIRELAB_CASES_FILE:-}                      # optional "name|syn|synack|rst|masscan args" lines
SEED=1; RATE=100
CREATED_A=0; CREATED_B=0; PIDS=()
mkdir -p "$OUT"; OUT=$(readlink -f "$OUT")
WORK="$OUT/.work"; rm -rf "$WORK"; mkdir -p "$WORK"
: >"$OUT/commands.txt"

log() { echo "[wire-lab] $*"; }
note_cmd() { echo "$*" >>"$OUT/commands.txt"; }

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  stop_suite_group
  local pid
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null; done
  sleep 0.3
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null; done
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && wait "$pid" 2>/dev/null; done
  [ "$CREATED_A" = 1 ] && ip netns del "$NS_A" 2>/dev/null
  [ "$CREATED_B" = 1 ] && ip netns del "$NS_B" 2>/dev/null
  local left; left=$(ip netns list 2>/dev/null | grep -c -- "$RUN_ID")
  rm -rf "$WORK"
  [ -n "${SUDO_UID:-}" ] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null
  log "cleanup: rc=$rc own_pids=${#PIDS[@]} namespaces_left=$left"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

nsa() { ip netns exec "$NS_A" "$@"; }
nsb() { ip netns exec "$NS_B" "$@"; }

start_bg() {  # start_bg LOGFILE cmd... ; sets BGPID, tracks it for cleanup
  local lf=$1; shift
  "$@" >"$lf" 2>&1 &
  BGPID=$!; PIDS+=("$BGPID")
}
stop_bg() {  # stop_bg PID : terminate one tracked child and reap it
  kill -TERM "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
wait_file() {  # wait_file PATH SECONDS
  local i; for i in $(seq 1 $(( $2 * 20 ))); do [ -e "$1" ] && return 0; sleep 0.05; done
  return 1
}

# ---- host-global facts that influence masscan: /etc/masscan/masscan.conf ------
CONF=/etc/masscan/masscan.conf; CONF_MASKED=0; EMPTY="$WORK/empty-etc-masscan"; mkdir -p "$EMPTY"
if [ -e "$CONF" ]; then CONF_MASKED=1; log "host $CONF exists (sha256 $(sha256sum "$CONF" | cut -d' ' -f1)); masking /etc/masscan in a private mount namespace"; fi
oracle_in() {  # oracle_in NS args... : run the oracle in namespace NS, host conf masked if present
  local ns=$1; shift
  if [ "$CONF_MASKED" = 1 ]; then
    ip netns exec "$ns" unshare -m sh -c 'mount --bind "$0" /etc/masscan && exec "$@"' "$EMPTY" "$ORACLE" "$@"
  else
    ip netns exec "$ns" "$ORACLE" "$@"
  fi
}

# ---- topology: two namespaces, one veth, no host-side link --------------------
host_links_before=$(ip -o link | awk -F': ' '{print $2}' | sort)
printf '%s\n' "$host_links_before" > "$WORK/host-links-before.txt"
ip netns add "$NS_A"; CREATED_A=1
ip netns add "$NS_B"; CREATED_B=1
note_cmd "ip netns add $NS_A; ip netns add $NS_B"
ip -n "$NS_A" link add "$IF_A" type veth peer name "$IF_B" netns "$NS_B"
note_cmd "ip -n $NS_A link add $IF_A type veth peer name $IF_B netns $NS_B"
for ns in "$NS_A" "$NS_B"; do
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 net.ipv4.ip_forward=0
done
ip -n "$NS_A" link set "$IF_A" address "$MAC_A"
ip -n "$NS_B" link set "$IF_B" address "$MAC_B"
nsa sysctl -qw "net.ipv6.conf.$IF_A.disable_ipv6=1"; nsb sysctl -qw "net.ipv6.conf.$IF_B.disable_ipv6=1"
[ -z "$IP_A_LINK" ] || ip -n "$NS_A" addr add "$IP_A_LINK/24" dev "$IF_A"
for ip_ in $PEER_IPS; do ip -n "$NS_B" addr add "$ip_/$PEER_PREFIX" dev "$IF_B"; done
ip -n "$NS_B" neigh add "$IP_ADAPTER" lladdr "$MAC_A" dev "$IF_B" nud permanent   # no ARP needed on the lab wire
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set "$IF_A" up
ip -n "$NS_B" link set "$IF_B" up
if [ "$SUITE" != oracle ]; then
  # veth hands CHECKSUM_PARTIAL frames to AF_PACKET readers: the peer kernel's SYN-ACK arrives with
  # an unfinished TCP checksum, which a verifying receiver (the Rust engine, unlike C) must reject.
  # A real NIC delivers valid checksums. Offload is disabled on this run's two veth ends only.
  command -v ethtool >/dev/null || { echo "FATAL: missing ethtool" >&2; exit 2; }
  ip netns exec "$NS_A" ethtool -K "$IF_A" tx off >/dev/null
  ip netns exec "$NS_B" ethtool -K "$IF_B" tx off >/dev/null
  note_cmd "ip netns exec \$NS_A ethtool -K $IF_A tx off; ip netns exec \$NS_B ethtool -K $IF_B tx off   # veth tx-checksum offload off, this run's veth only"
fi

# ---- seal assertions (fail closed) ------------------------------------------
fail() { echo "FATAL: $*" >&2; exit 3; }
for ns in "$NS_A" "$NS_B"; do
  [ -z "$(ip -n "$ns" route show default)" ] || fail "$ns has a default route"
  [ -z "$(ip -n "$ns" -6 route show default)" ] || fail "$ns has an IPv6 default route"
  links=$(ip -n "$ns" -o link | awk -F': ' '{print $2}' | sed 's/@.*//' | sort | tr '\n' ' ')
  case "$ns" in "$NS_A") want="lo $IF_A ";; *) want="lo $IF_B ";; esac
  [ "$links" = "$want" ] || fail "$ns links '$links' != '$want'"
  ip -n "$ns" -d link | grep -Eq 'bridge|master|bond|vlan|macvlan' && fail "$ns has a bridge/master/virtual upper device"
  [ "$(ip netns exec "$ns" cat /proc/sys/net/ipv4/ip_forward)" = 0 ] || fail "$ns ip_forward != 0"
  ip netns exec "$ns" ip route get 8.8.8.8 >/dev/null 2>&1 && fail "$ns can route to 8.8.8.8"
  [ "$(ip -n "$ns" route show | grep -c .)" -le 1 ] || fail "$ns has more than the connected route"
done
[ "$(ip -o link | awk -F': ' '{print $2}' | sort)" = "$host_links_before" ] || fail "host link list changed"
note_cmd "ip -n \$NS route show default (empty); ip -n \$NS route get 8.8.8.8 (fails)  # seal assertions, both namespaces"
"$LAB_BIN" capture isolation --out "$OUT/isolation.json" --ns-a "$NS_A" --ns-b "$NS_B" --host-links-before "$WORK/host-links-before.txt"

topo() {  # topo FILE : save topology + routes of both namespaces
  { echo "# host namespace links (must not contain veth-a/veth-b)"; ip -o link | awk -F': ' '{print $2}'
    for ns in "$NS_A" "$NS_B"; do
      echo; echo "# ===== namespace $ns ====="
      echo "## ip -d link"; ip -n "$ns" -d link show
      echo "## ip -4 addr"; ip -n "$ns" -4 addr show
      echo "## ip route"; ip -n "$ns" route show
      echo "## ip -6 route"; ip -n "$ns" -6 route show
      echo "## ip rule"; ip -n "$ns" rule show
      echo "## ip neigh"; ip -n "$ns" neigh show
      echo "## ip_forward"; ip netns exec "$ns" cat /proc/sys/net/ipv4/ip_forward
      echo "## tx checksum offload"; ip netns exec "$ns" ethtool -k "$( [ "$ns" = "$NS_A" ] && echo $IF_A || echo $IF_B )" 2>/dev/null | grep -E '^tx-checksumming' || true
    done; } | sed -E "s/wl-(scan|peer)-[0-9]+-[0-9]+/wl-\1-RUNID/g" >"$1"
}

# ---- responder in the peer namespace (open: $OPEN_PORTS; the rest get kernel RST)
RESP_PID=""
if [ "$SUITE" = oracle ]; then
  start_bg "$WORK/responder.log" ip netns exec "$NS_B" "$LAB_BIN" capture responder --ports "$OPEN_PORTS" --ready "$WORK/responder.ready"
  RESP_PID=$BGPID
  note_cmd "ip netns exec \$NS_B rmasscan-lab capture responder --ports $OPEN_PORTS --ready READY"
  wait_file "$WORK/responder.ready" 10 || fail "responder not ready"
else
  # rust/perf suites: rmasscan-lab wire-suite restarts its own responder before EVERY run, because the peer kernel
  # keeps retransmitting SYN-ACKs of half-open sockets for ~1 minute (the Rust scanner never RSTs them)
  # and those would bleed into the next run's capture.
  note_cmd "(rmasscan-lab wire-suite) ip netns exec \$NS_B rmasscan-lab capture responder --ports $OPEN_PORTS ...   # restarted before every run"
fi

"$LAB_BIN" capture env --out "$OUT/env.json" --oracle "$ORACLE" --ns-a "$NS_A" --ns-b "$NS_B" \
  --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" --ip-a "$IP_ADAPTER" --peer-ips "$PEER_IPS" \
  --seed "$SEED" --rate "$RATE" --open-ports "$OPEN_PORTS" --conf-masked "$CONF_MASKED" \
  --wire-lab-sh "$HERE/wire-lab.sh" --process-group-sh "$HERE/lab-process-group.sh" \
  ${RMASSCAN_DEPLOY_MANIFEST:+--deploy-manifest "$RMASSCAN_DEPLOY_MANIFEST"}
sed -i -E "s/wl-(scan|peer)-[0-9]+-[0-9]+/wl-\1-RUNID/g" "$OUT/env.json"
topo "$OUT/topology-before.txt"          # topology + routes are saved BEFORE any scanner traffic

case "${WIRELAB_INJECT:-}" in
  error) log "injected error"; false ;;
  hang) log "injected hang"; sleep 600 & PIDS+=($!); wait $! ;;
esac

if [ "$SUITE" = oracle ]; then
# ---- cases: name | expected SYN | expected SYN-ACK | expected RST | masscan targets/options
COMMON=(--interface "$IF_A" --adapter-ip "$IP_ADAPTER" --adapter-mac "$MAC_A" --router-mac "$MAC_B"
        --seed "$SEED" --rate "$RATE" --blackrock-rounds 14 --retries 0 --wait 3)
if [ -n "$CASES_FILE" ]; then
  mapfile -t CASES <"$CASES_FILE"
else
CASES=(
"c01_one_addr_port_synack|1|1|0|10.200.0.2 -p80 --source-port 40000"
"c02_one_addr_port_rst|1|0|1|10.200.0.2 -p81 --source-port 40000"
"c03_multi_addr_ports|16|8|8|10.200.0.2-10.200.0.5 -p80,81,443,8080 --source-port 40000"
"c04_exclude|6|3|3|10.200.0.2-10.200.0.5 -p80,81 --exclude 10.200.0.3 --source-port 40000"
"c05_srcport_single|4|2|2|10.200.0.2-10.200.0.3 -p80,81 --source-port 50123"
"c06_srcport_range|4|2|2|10.200.0.2-10.200.0.3 -p80,81 --source-port 50000-50015"
)
fi
: >"$OUT/cases.tsv"
for row in "${CASES[@]}"; do
  IFS='|' read -r name e_syn e_synack e_rst margs <<<"$row"
  read -r -a MARGS <<<"$margs"
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$e_syn" "$e_synack" "$e_rst" "$margs" >>"$OUT/cases.tsv"
  note_cmd "ip netns exec \$NS_A timeout 60 ORACLE ${MARGS[*]} ${COMMON[*]} -oL CASE.scan.txt   # case $name, 2 runs"
  oracle_in "$NS_A" "${MARGS[@]}" "${COMMON[@]}" --echo >"$OUT/$name.echo" 2>"$WORK/echo.err"
  for run in 1 2; do
    pfx="$name.run$run"
    rm -f "$WORK/rec.ready" "$WORK/rec.ack"
    start_bg "$WORK/rec.log" ip netns exec "$NS_B" "$LAB_BIN" capture dump --iface "$IF_B" \
      --pcap "$OUT/$pfx.pcap" --meta "$OUT/$pfx.capture.json" --ready "$WORK/rec.ready" --ack "$WORK/rec.ack" --end-dst "$MAC_A"
    REC_PID=$BGPID
    wait_file "$WORK/rec.ready" 30 || fail "tcpdump witness not ready ($pfx)"
    nsa "$LAB_BIN" capture marker --iface "$IF_A" --src "$MAC_A" --dst "$MAC_B"
    wait_file "$WORK/rec.ack" 15 || fail "tcpdump never captured the start marker frame ($pfx)"
    # capture is live and acknowledged; only now does the scanner start
    if [ "$CONF_MASKED" = 1 ]; then  # host conf masked inside a private mount namespace
      start_bg "$WORK/scan.log" ip netns exec "$NS_A" timeout 60 unshare -m sh -c 'mount --bind "$0" /etc/masscan && exec "$@"' "$EMPTY" "$ORACLE" "${MARGS[@]}" "${COMMON[@]}" -oL "$OUT/$pfx.scan.txt"
    else
      start_bg "$WORK/scan.log" ip netns exec "$NS_A" timeout 60 "$ORACLE" "${MARGS[@]}" "${COMMON[@]}" -oL "$OUT/$pfx.scan.txt"
    fi
    SCAN_PID=$BGPID
    wait "$SCAN_PID" || fail "oracle failed ($pfx): $(tail -3 "$WORK/scan.log")"
    sleep 0.5
    stop_bg "$REC_PID"   # SIGTERM: the witness waits for quiet, sends end markers, stops tcpdump, writes the meta
    cp "$WORK/scan.log" "$OUT/$pfx.oracle-stderr.txt"
    log "$pfx done: $("$LAB_BIN" capture summary --meta "$OUT/$pfx.capture.json")"
  done
done

fi

if [ "$SUITE" != oracle ]; then
  # ---- Rust suites: driver runs inside this sealed lab; its own children die with it
  note_cmd "rmasscan-lab wire-suite --suite $SUITE ...   # runs everything through ip netns exec \$NS_A / \$NS_B"
  start_suite_group "$OUT/suite.log" "$LAB_BIN" wire-suite --suite "$SUITE" --out "$OUT" --work "$WORK" \
    --ns-a "$NS_A" --ns-b "$NS_B" --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" \
    --ip-a "$IP_ADAPTER" --rust-bin "$RUST_BIN" --oracle "$ORACLE" --fixtures "$FIXTURES" \
    --conf-masked "$CONF_MASKED" --empty-dir "$EMPTY" --reps "$REPS" --rates "$RATES"
  SUITE_PID=$SUITE_PGID
  SUITE_RC=0; wait "$SUITE_PID" || SUITE_RC=$?
  stop_suite_group
  log "suite $SUITE finished rc=$SUITE_RC (see $OUT/suite.log, results.json)"
fi

topo "$OUT/topology-after.txt"
[ -z "$RESP_PID" ] || stop_bg "$RESP_PID"
if [ "$SUITE" = oracle ]; then
  "$LAB_BIN" capture manifest --dir "$OUT"
  log "done: $OUT/manifest.json"
else
  log "done: $OUT/results.json"
  exit "${SUITE_RC:-0}"
fi
