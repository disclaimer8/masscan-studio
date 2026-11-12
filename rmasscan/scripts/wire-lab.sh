#!/usr/bin/env bash
# Sealed Linux wire lab: runs the ORIGINAL pinned C masscan between two network
# namespaces joined by a veth pair and records the peer-side wire as classic pcap.
#
#   wire-lab.sh --oracle /path/to/masscan --out DIR                       # C oracle capture (default suite)
#   wire-lab.sh --oracle BIN --out DIR --suite rust --rust-bin WIRE_SCAN --fixtures tests/golden/wire
#   wire-lab.sh --oracle BIN --out DIR --suite perf --rust-bin WIRE_SCAN [--reps 5] [--rates 100,1000,10000,100000]
#   wire-lab.sh --oracle BIN --out DIR --suite autodetect --rmasscan RMASSCAN_CLI
#   wire-lab.sh --oracle BIN --out DIR --suite output --rmasscan RMASSCAN_CLI
#   wire-lab.sh --oracle BIN --out DIR --suite scan-control --rmasscan RMASSCAN_CLI
#   wire-lab.sh --oracle BIN --out DIR --suite protocols --rmasscan RMASSCAN_CLI
#   wire-lab.sh --oracle BIN --out DIR --suite ipv6 --rmasscan RMASSCAN_CLI
#
# Suite autodetect runs rmasscan-lab autodetect-suite linux inside the lab, with ONE controlled change to the
# seal: the scanner namespace gets a default route via the peer (198.18.0.2) and permanent neighbours for
# 198.18.0.2-5, so the rmasscan CLI can auto-detect its interface, source IP and router. The peer namespace
# still has no default route; the stand is fixed inside this script (the WIRELAB_* stand overrides, MACs, ports and cases file included, are ignored).
# Its cleanup records the undo in OUT/teardown.json under the lab id it gave the suite, and keeps OUT/.work when the
# suite marked it (work-kept.txt); an OUT holding earlier suite output is refused: every lab gets a new --out.
# Suite output runs rmasscan-lab output-suite linux on the same autodetect stand (same seal, lab id, teardown record,
# kept work and refusal of an earlier lab's OUT): the C oracle and rmasscan in every masscan output format.
#
# Suite scan-control runs rmasscan-lab scan-control-suite linux on the autodetect stand (same seal, lab id, teardown
# record, kept work and refusal of an earlier lab's OUT) plus ONE more veth pair for `--adapter[1]`, created inside the
# same two namespaces (veth-a2 in the scanner namespace, veth-b2 moved straight into the peer one): no address on
# either end, a /32 route to 198.18.0.6 and its permanent neighbour on the peer end only; 198.18.0.6 is assigned to
# no interface (rmasscan binds it itself). Both pairs die with the two namespaces in the same cleanup trap; no
# host interface is ever created, touched or listed.
#
# Suite protocols runs rmasscan-lab protocols-suite linux on the autodetect stand (same seal, lab id, teardown record,
# kept work and refusal of an earlier lab's OUT) with ONE more controlled change, in the peer namespace only:
# net.ipv4.icmp_ratemask=0, so the peer kernel sends every ICMP error it owes (each closed UDP probe gets its ICMP 3/3)
# instead of rate-limiting them. The suite's own responder answers UDP and SCTP; it never loads a kernel module and
# refuses the SCTP cases when the host kernel has SCTP. The setting dies with the namespace.
#
# Suite ipv6 runs rmasscan-lab ipv6-suite linux on the autodetect stand (same seal, lab id, teardown record, kept work
# and refusal of an earlier lab's OUT) with IPv6 raised on the lab veth pair and the two namespaces' lo ONLY, and only
# for this suite: every line above that disables IPv6 runs as for the other suites first. On each veth end, while
# IPv6 is still off and the link down: no Duplicate Address Detection, no router solicitation or advertisement, no
# forwarding, EUI-64 link-local addresses (the IPV6_SETTINGS line); then the ULA fd00:198:18::1/64 on veth-a,
# fd00:198:18::2-5/64 on veth-b (nodad), in the scanner namespace an IPv6 default route via the peer's link-local
# fe80::aa:ff:fe00:2 and permanent IPv6 neighbours for the peers and the peer's link-local, in the peer namespace the
# scanner and its link-local as permanent neighbours (a learnt link-local entry is probed by NUD, live 7b r1), and a
# settle wait so that the kernels' MLD reports for the new groups are over before any capture.
# Every setting dies with the namespaces; the seal is `capture isolation --mode ipv6`.
#
# Suites rust/perf run rmasscan-lab wire-suite inside the same sealed lab (same seal assertions,
# same cleanup); `rust` ends by deleting the veth on purpose, so it is the last thing it does.
#
# SEALED: no uplink, no bridge, no NAT, no default route, ip_forward=0, IPv6 off (suite ipv6: on the lab veth only).
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
ORACLE=""; OUT=""; SUITE=oracle; RUST_BIN=""; RMASSCAN_BIN=""; FIXTURES=""; REPS=5; RATES=100,1000,10000,100000
while [ $# -gt 0 ]; do
  case "$1" in
    --oracle) ORACLE=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --suite) SUITE=$2; shift 2 ;;
    --rust-bin) RUST_BIN=$2; shift 2 ;;
    --fixtures) FIXTURES=$2; shift 2 ;;
    --rmasscan) RMASSCAN_BIN=$2; shift 2 ;;
    --reps) REPS=$2; shift 2 ;;
    --rates) RATES=$2; shift 2 ;;
    -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
[ -n "$ORACLE" ] && [ -n "$OUT" ] || { echo "usage: wire-lab.sh --oracle BIN --out DIR" >&2; exit 64; }
case "$SUITE" in oracle) ;; rust|perf) [ -n "$RUST_BIN" ] || { echo "--suite $SUITE needs --rust-bin" >&2; exit 64; } ;; autodetect) [ -n "$RMASSCAN_BIN" ] || { echo "--suite autodetect needs --rmasscan" >&2; exit 64; } ;; output) [ -n "$RMASSCAN_BIN" ] || { echo "--suite output needs --rmasscan" >&2; exit 64; } ;; scan-control) [ -n "$RMASSCAN_BIN" ] || { echo "--suite scan-control needs --rmasscan" >&2; exit 64; } ;; protocols) [ -n "$RMASSCAN_BIN" ] || { echo "--suite protocols needs --rmasscan" >&2; exit 64; } ;; ipv6) [ -n "$RMASSCAN_BIN" ] || { echo "--suite ipv6 needs --rmasscan" >&2; exit 64; } ;; *) echo "unknown suite: $SUITE" >&2; exit 64 ;; esac
[ "$SUITE" != rust ] || [ -n "$FIXTURES" ] || { echo "--suite rust needs --fixtures" >&2; exit 64; }
[ "$(uname -s)" = Linux ] || { echo "FATAL: Linux only" >&2; exit 2; }
if [ "$(id -u)" != 0 ]; then
  mkdir -p "$OUT"
  REEXEC=(--oracle "$(readlink -f "$ORACLE")" --out "$(readlink -f "$OUT")" --suite "$SUITE" --reps "$REPS" --rates "$RATES")
  [ -z "$RUST_BIN" ] || REEXEC+=(--rust-bin "$(readlink -f "$RUST_BIN")")
  [ -z "$RMASSCAN_BIN" ] || REEXEC+=(--rmasscan "$(readlink -f "$RMASSCAN_BIN")")
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
# The second pair of the scan-control stand (see the header): fixed here, like the rest of the stand.
IF_A2=veth-a2; IF_B2=veth-b2; MAC_A2=02:aa:00:00:00:03; MAC_B2=02:aa:00:00:00:04; IP_ADAPTER2=198.18.0.6
# The IPv6 stand of the ipv6 suite (see the header): fixed here too. The settings are the Rust IPV6_SYSCTLS, written
# while IPv6 is still off; disable_ipv6=0 comes last.
IP6_A=fd00:198:18::1; IP6_PEERS="fd00:198:18::2 fd00:198:18::3 fd00:198:18::4 fd00:198:18::5"; IP6_GW=fe80::aa:ff:fe00:2; IP6_A_LL=fe80::aa:ff:fe00:1
IPV6_SETTINGS="accept_dad=0 accept_ra=0 router_solicitations=0 forwarding=0 addr_gen_mode=0 disable_ipv6=0"
# The defaults are the Linux binding. The Windows stand overrides them (same script, same capture path) with
# WIRELAB_* so that the C oracle fixtures use the SAME source IP/MAC and peer MAC as the real Windows run.
MAC_A=${WIRELAB_MAC_A:-02:aa:00:00:00:01}; MAC_B=${WIRELAB_MAC_B:-02:aa:00:00:00:02}
IP_A_LINK=${WIRELAB_IP_A_LINK-10.200.0.1}             # empty = no address on the scanner end
IP_ADAPTER=${WIRELAB_IP_ADAPTER:-10.200.0.100}         # adapter IP is NOT assigned to any interface
PEER_IPS=${WIRELAB_PEER_IPS:-"10.200.0.2 10.200.0.3 10.200.0.4 10.200.0.5"}
PEER_PREFIX=${WIRELAB_PEER_PREFIX:-24}
OPEN_PORTS=${WIRELAB_OPEN_PORTS:-80,8080}               # responder listens here; every other port gets RST
CASES_FILE=${WIRELAB_CASES_FILE:-}                      # optional "name|syn|synack|rst|masscan args" lines
DEFAULT_VIA=""
# The suites that run on the autodetect stand (the Rust driver inside the lab, a lab id, a teardown record).
STAND_SUITE=0; case "$SUITE" in autodetect|output|scan-control|protocols) STAND_SUITE=1 ;; esac
# ipv6: the same stand, IPv6 raised on its veth pair only (see the header)
[ "$SUITE" != ipv6 ] || STAND_SUITE=1
if [ "$STAND_SUITE" = 1 ]; then
  # Fixed stand of the autodetect and output suites (inside the script on purpose: no new variable crosses the sudo -n env re-exec).
  # The scanner's own address is assigned to veth-a, so the adapter IP is the link address.
  IP_A_LINK=198.18.0.1; IP_ADAPTER=198.18.0.1; PEER_IPS="198.18.0.2 198.18.0.3 198.18.0.4 198.18.0.5"; PEER_PREFIX=24
  DEFAULT_VIA=198.18.0.2
  MAC_A=02:aa:00:00:00:01; MAC_B=02:aa:00:00:00:02; OPEN_PORTS=80,8080; CASES_FILE=""
fi
SEED=1; RATE=100
CREATED_A=0; CREATED_B=0; PIDS=()
STOP_GRACE=45   # witness: quiet wait <= 20 s + end markers <= 15 s + tcpdump stop <= 30 s, but normally 2-3 s
mkdir -p "$OUT"; OUT=$(readlink -f "$OUT")
LAB_ID=""
if [ "$STAND_SUITE" = 1 ]; then
  # An earlier lab's directory is never reused: its runs, its teardown record (or the lack of one, if its cleanup
  # died) and a work directory the suite kept after a failed evidence copy (the rm below would wipe it) all stay
  # its own, so a new lab needs a new --out.
  for f in manifest.json runs runs_aborted teardown.json .work; do
    if [ -e "$OUT/$f" ] || [ -L "$OUT/$f" ]; then
      echo "FATAL: $OUT/$f exists: $OUT holds the output of an earlier $SUITE lab; use a new --out" >&2; exit 2
    fi
  done
  # This lab's id: the suite keeps it in manifest.json and the cleanup writes it into teardown.json, which binds the
  # record of the undo to this lab's runs.
  LAB_ID=$(cat /proc/sys/kernel/random/uuid) || { echo "FATAL: cannot generate the lab id" >&2; exit 2; }
fi
WORK="$OUT/.work"; rm -rf "$WORK"; mkdir -p "$WORK"
: >"$OUT/commands.txt"

log() { echo "[wire-lab] $*"; }
note_cmd() { echo "$*" >>"$OUT/commands.txt"; }

# The undo of the autodetect stand as evidence ($OUT/teardown.json, judged by autodetect-verify): the lab id the
# suite has in manifest.json, which of this run's namespaces are gone once cleanup deleted them (names scrubbed like
# env.json), and how many are still listed, by exact name; null when `ip netns list` fails, so that no count stands
# in for an unread list.
autodetect_teardown() {
  local list names left=null deleted="" created_ns created ns
  if list=$(ip netns list 2>/dev/null); then
    left=$(printf '%s\n' "$list" | grep -cE "^wl-(scan|peer)-$RUN_ID( |\$)")
    names=$(printf '%s\n' "$list" | awk '{print $1}')
    for created_ns in "$CREATED_A:$NS_A" "$CREATED_B:$NS_B"; do
      created=${created_ns%%:*}; ns=${created_ns#*:}
      [ "$created" = 1 ] || continue
      case $'\n'"$names"$'\n' in *$'\n'"$ns"$'\n'*) continue ;; esac
      deleted="$deleted${deleted:+,}\"$(printf '%s' "$ns" | sed -E 's/wl-(scan|peer)-[0-9]+-[0-9]+/wl-\1-RUNID/')\""
    done
  fi
  printf '{"lab_id":"%s","namespaces_deleted":[%s],"namespaces_left":%s}\n' "$LAB_ID" "$deleted" "$left" >"$OUT/teardown.json"
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  stop_suite_group
  # Each background child is the leader of its own session (start_bg). The leader is TERMed alone and
  # given STOP_GRACE seconds (the capture witness needs its quiescence wait, end markers, tcpdump stop
  # and meta write); then the whole session, including a tcpdump child, is TERMed and KILLed.
  local pid stray=0
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && { stop_session "$pid" "$STOP_GRACE" || stray=$((stray + 1)); }; done
  [ "$CREATED_A" = 1 ] && ip netns del "$NS_A" 2>/dev/null
  [ "$CREATED_B" = 1 ] && ip netns del "$NS_B" 2>/dev/null
  # nothing of this run may outlive it: no tcpdump writing into OUT, no live member of a tracked session
  stray=$((stray + $(stray_processes tcpdump "$OUT/")))
  # this run's two namespaces by exact name (a substring would also count wl-scan-14321-123456 for RUN_ID 4321-12345)
  local left; left=$(ip netns list 2>/dev/null | grep -cE "^wl-(scan|peer)-$RUN_ID( |\$)")
  [ "$STAND_SUITE" = 0 ] || autodetect_teardown
  # The autodetect suite marks a work directory it kept after a failed evidence copy: that one stays for inspection.
  if [ "$SUITE" = autodetect ] && [ -e "$WORK/work-kept.txt" ]; then
    log "cleanup: $WORK kept: the suite could not copy a run into the evidence directory (see work-kept.txt); inspect it, never publish it"
  elif [ "$STAND_SUITE" = 1 ] && [ -e "$WORK/work-kept.txt" ]; then
    log "cleanup: $WORK kept: the suite could not copy a run into the evidence directory (see work-kept.txt); inspect it, never publish it"
  else
    rm -rf "$WORK"
  fi
  [ -n "${SUDO_UID:-}" ] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null
  log "cleanup: rc=$rc own_pids=${#PIDS[@]} stray_processes=$stray namespaces_left=$left"
  # a leftover process or namespace is a failure of the run even when the body succeeded
  if [ "$rc" = 0 ] && { [ "$left" -gt 0 ] || [ "$stray" -gt 0 ]; }; then rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

nsa() { ip netns exec "$NS_A" "$@"; }
nsb() { ip netns exec "$NS_B" "$@"; }

start_bg() {  # start_bg LOGFILE cmd... ; sets BGPID, tracks it for cleanup
  local lf=$1; shift
  start_bg_session "$lf" "$@"
  PIDS+=("$BGPID")
}
stop_bg() {  # stop_bg PID : stop one tracked child (leader first, bounded), sweep its session, reap it
  local i
  stop_session "$1" "$STOP_GRACE" || true
  for i in "${!PIDS[@]}"; do [ "${PIDS[$i]}" = "$1" ] && PIDS[$i]=""; done   # a stopped session id is never signalled again
  return 0  # the loop's last test is usually false; under set -e that status would abort the caller
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
if [ "$SUITE" = scan-control ]; then
  # The second pair, inside the scanner namespace with its peer end moved straight into the peer one; if the
  # creation fails, the trap deletes both namespaces and the half-made pair goes with them.
  ip -n "$NS_A" link add "$IF_A2" type veth peer name "$IF_B2" netns "$NS_B"
  note_cmd "ip -n $NS_A link add $IF_A2 type veth peer name $IF_B2 netns $NS_B   # scan-control: the second pair, same namespaces"
fi
for ns in "$NS_A" "$NS_B"; do
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 net.ipv4.ip_forward=0
done
ip -n "$NS_A" link set "$IF_A" address "$MAC_A"
ip -n "$NS_B" link set "$IF_B" address "$MAC_B"
nsa sysctl -qw "net.ipv6.conf.$IF_A.disable_ipv6=1"; nsb sysctl -qw "net.ipv6.conf.$IF_B.disable_ipv6=1"
# protocols: the peer kernel sends every ICMP error it owes (no rate limit), in the peer namespace only.
[ "$SUITE" != protocols ] || nsb sysctl -qw net.ipv4.icmp_ratemask=0
[ "$SUITE" != protocols ] || note_cmd "ip netns exec \$NS_B sysctl -qw net.ipv4.icmp_ratemask=0   # protocols: every ICMP error of the peer kernel is sent"
if [ "$SUITE" = scan-control ]; then
  ip -n "$NS_A" link set "$IF_A2" address "$MAC_A2"
  ip -n "$NS_B" link set "$IF_B2" address "$MAC_B2"
  nsa sysctl -qw "net.ipv6.conf.$IF_A2.disable_ipv6=1"; nsb sysctl -qw "net.ipv6.conf.$IF_B2.disable_ipv6=1"
fi
if [ "$SUITE" = ipv6 ]; then
  # ipv6: IPv6 back on for the lab veth pair and lo only, in both namespaces, links still down. DAD is off for the
  # namespace too (the kernel runs it while either `all` or the link asks for it).
  for kv in $IPV6_SETTINGS; do nsa sysctl -qw "net.ipv6.conf.$IF_A.$kv"; nsb sysctl -qw "net.ipv6.conf.$IF_B.$kv"; done
  for ns in "$NS_A" "$NS_B"; do ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.lo.disable_ipv6=0; done
  note_cmd "ip netns exec \$NS sysctl -qw net.ipv6.conf.{$IF_A,$IF_B}.{$IPV6_SETTINGS} net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.lo.disable_ipv6=0   # ipv6: IPv6 on the lab veth pair only"
fi
[ -z "$IP_A_LINK" ] || ip -n "$NS_A" addr add "$IP_A_LINK/24" dev "$IF_A"
for ip_ in $PEER_IPS; do ip -n "$NS_B" addr add "$ip_/$PEER_PREFIX" dev "$IF_B"; done
ip -n "$NS_B" neigh add "$IP_ADAPTER" lladdr "$MAC_A" dev "$IF_B" nud permanent   # no ARP needed on the lab wire
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set "$IF_A" up
ip -n "$NS_B" link set "$IF_B" up
if [ "$SUITE" = scan-control ]; then
  ip -n "$NS_A" link set "$IF_A2" up
  ip -n "$NS_B" link set "$IF_B2" up
  # No address on either end: the peer answers the second adapter through a host route and a permanent neighbour
  # on its own end, and the scanner binds 198.18.0.6 itself (it is assigned to no interface).
  ip -n "$NS_B" route add "$IP_ADAPTER2/32" dev "$IF_B2"
  ip -n "$NS_B" neigh add "$IP_ADAPTER2" lladdr "$MAC_A2" dev "$IF_B2" nud permanent
  note_cmd "ip -n \$NS_B route add $IP_ADAPTER2/32 dev $IF_B2; ip -n \$NS_B neigh add $IP_ADAPTER2 lladdr $MAC_A2 dev $IF_B2 nud permanent   # scan-control: the second adapter's return path"
fi
if [ -n "$DEFAULT_VIA" ]; then
  # autodetect: the one controlled change. Default route via the peer and permanent neighbours, both in NS_A only.
  ip -n "$NS_A" route add default via "$DEFAULT_VIA" dev "$IF_A"
  for ip_ in $PEER_IPS; do ip -n "$NS_A" neigh add "$ip_" lladdr "$MAC_B" dev "$IF_A" nud permanent; done
  note_cmd "ip -n \$NS_A route add default via $DEFAULT_VIA dev $IF_A; ip -n \$NS_A neigh add {$PEER_IPS} lladdr $MAC_B dev $IF_A nud permanent   # autodetect stand"
fi
if [ "$SUITE" = ipv6 ]; then
  # ipv6: the ULA addresses without DAD, the scanner's IPv6 default route via the peer's link-local (several on-link
  # targets resolve the interface's default gateway, so rmasscan's NS goes to the router), and permanent neighbours on
  # both ends: no kernel needs to solicit on the wire (rmasscan's resolver does not read the neighbour table), and the
  # peer answers the C oracle without asking the scanner, which C never answers. The link-local addresses are
  # permanent too: live (7b r1) the scanner kernel learnt the router's link-local (a route lookup via the default route
  # probes the router) and the peer the scanner's, and NUD later probed both with unicast NS inside a step.
  ip -n "$NS_A" -6 addr add "$IP6_A/64" dev "$IF_A" nodad
  for ip_ in $IP6_PEERS; do ip -n "$NS_B" -6 addr add "$ip_/64" dev "$IF_B" nodad; done
  ip -n "$NS_A" -6 route add default via "$IP6_GW" dev "$IF_A"
  for ip_ in $IP6_PEERS; do ip -n "$NS_A" -6 neigh add "$ip_" lladdr "$MAC_B" dev "$IF_A" nud permanent; done
  ip -n "$NS_B" -6 neigh add "$IP6_A" lladdr "$MAC_A" dev "$IF_B" nud permanent
  ip -n "$NS_A" -6 neigh add "$IP6_GW" lladdr "$MAC_B" dev "$IF_A" nud permanent
  ip -n "$NS_B" -6 neigh add "$IP6_A_LL" lladdr "$MAC_A" dev "$IF_B" nud permanent
  note_cmd "ip -n \$NS_A -6 addr add $IP6_A/64 dev $IF_A nodad; ip -n \$NS_B -6 addr add {$IP6_PEERS}/64 dev $IF_B nodad; ip -n \$NS_A -6 route add default via $IP6_GW dev $IF_A; ip -n \$NS_A -6 neigh add {$IP6_PEERS} $IP6_GW lladdr $MAC_B dev $IF_A nud permanent; ip -n \$NS_B -6 neigh add $IP6_A $IP6_A_LL lladdr $MAC_A dev $IF_B nud permanent   # ipv6 stand"
  # The kernels' MLD reports for the groups just joined repeat for up to mldv2_unsolicited_report_interval (1 s):
  # they are over before the first capture starts (live 7b r1: no MLD frame in any step).
  sleep 3
fi
if [ "$SUITE" != oracle ]; then
  # veth hands CHECKSUM_PARTIAL frames to AF_PACKET readers: the peer kernel's SYN-ACK arrives with
  # an unfinished TCP checksum, which a verifying receiver (the Rust engine, unlike C) must reject.
  # A real NIC delivers valid checksums. Offload is disabled on this run's two veth ends only.
  command -v ethtool >/dev/null || { echo "FATAL: missing ethtool" >&2; exit 2; }
  ip netns exec "$NS_A" ethtool -K "$IF_A" tx off >/dev/null
  ip netns exec "$NS_B" ethtool -K "$IF_B" tx off >/dev/null
  note_cmd "ip netns exec \$NS_A ethtool -K $IF_A tx off; ip netns exec \$NS_B ethtool -K $IF_B tx off   # veth tx-checksum offload off, this run's veth only"
  if [ "$SUITE" = scan-control ]; then
    ip netns exec "$NS_A" ethtool -K "$IF_A2" tx off >/dev/null
    ip netns exec "$NS_B" ethtool -K "$IF_B2" tx off >/dev/null
    note_cmd "ip netns exec \$NS_A ethtool -K $IF_A2 tx off; ip netns exec \$NS_B ethtool -K $IF_B2 tx off   # the second pair, this run's veth only"
  fi
fi

# ---- seal assertions (fail closed) ------------------------------------------
fail() { echo "FATAL: $*" >&2; exit 3; }
for ns in "$NS_A" "$NS_B"; do
  if [ -n "$DEFAULT_VIA" ] && [ "$ns" = "$NS_A" ]; then :; else
    [ -z "$(ip -n "$ns" route show default)" ] || fail "$ns has a default route"
  fi
  if [ "$SUITE" = ipv6 ] && [ "$ns" = "$NS_A" ]; then
    # ipv6 scanner namespace: exactly one IPv6 default route, via the peer's link-local on the lab veth
    [ "$(ip -n "$ns" -6 route show default | grep -c .)" = 1 ] && ip -n "$ns" -6 route show default | grep -Eq "^default via $IP6_GW dev $IF_A( |\$)" || fail "$ns IPv6 default route is not exactly via $IP6_GW dev $IF_A"
  else
    [ -z "$(ip -n "$ns" -6 route show default)" ] || fail "$ns has an IPv6 default route"
    if [ "$SUITE" = ipv6 ]; then
      ip netns exec "$ns" ip -6 route get 2001:db8::1 >/dev/null 2>&1 && fail "$ns can route to 2001:db8::1"
    fi
  fi
  links=$(ip -n "$ns" -o link | awk -F': ' '{print $2}' | sed 's/@.*//' | sort | tr '\n' ' ')
  case "$ns" in "$NS_A") want="lo $IF_A ";; *) want="lo $IF_B ";; esac
  if [ "$SUITE" = scan-control ]; then
    case "$ns" in "$NS_A") want="lo $IF_A $IF_A2 ";; *) want="lo $IF_B $IF_B2 ";; esac
  fi
  [ "$links" = "$want" ] || fail "$ns links '$links' != '$want'"
  ip -n "$ns" -d link | grep -Eq 'bridge|master|bond|vlan|macvlan' && fail "$ns has a bridge/master/virtual upper device"
  [ "$(ip netns exec "$ns" cat /proc/sys/net/ipv4/ip_forward)" = 0 ] || fail "$ns ip_forward != 0"
  if [ -n "$DEFAULT_VIA" ] && [ "$ns" = "$NS_A" ]; then
    # autodetect scanner namespace: exactly the connected route and the default route via the peer
    [ "$(ip -n "$ns" route show | grep -c .)" = 2 ] || fail "$ns routes are not exactly two"
    ip -n "$ns" route show | grep -Eq "^198\.18\.0\.0/24 dev $IF_A( |\$)" || fail "$ns lacks 198.18.0.0/24 dev $IF_A"
    ip -n "$ns" route show | grep -Eq "^default via $DEFAULT_VIA dev $IF_A( |\$)" || fail "$ns lacks default via $DEFAULT_VIA dev $IF_A"
    ip netns exec "$ns" ip route get 8.8.8.8 | head -n1 | grep -Eq "^8\.8\.8\.8 via $DEFAULT_VIA dev $IF_A( |\$)" || fail "$ns route get 8.8.8.8 is not via $DEFAULT_VIA dev $IF_A"
  else
    ip netns exec "$ns" ip route get 8.8.8.8 >/dev/null 2>&1 && fail "$ns can route to 8.8.8.8"
    if [ "$SUITE" = scan-control ] && [ "$ns" = "$NS_B" ]; then
      # the connected route and the one /32 route of the second adapter, nothing else
      [ "$(ip -n "$ns" route show | grep -c .)" = 2 ] || fail "$ns routes are not exactly the connected route and the second adapter's"
      ip -n "$ns" route show | grep -Eq "^$IP_ADAPTER2 dev $IF_B2( |\$)" || fail "$ns lacks $IP_ADAPTER2 dev $IF_B2"
    else
      [ "$(ip -n "$ns" route show | grep -c .)" -le 1 ] || fail "$ns has more than the connected route"
    fi
  fi
done
[ "$(ip -o link | awk -F': ' '{print $2}' | sort)" = "$host_links_before" ] || fail "host link list changed"
if [ -n "$DEFAULT_VIA" ]; then
  note_cmd "ip -n \$NS_A route show (exactly: 198.18.0.0/24 dev $IF_A; default via $DEFAULT_VIA dev $IF_A); ip -n \$NS_A route get 8.8.8.8 (via $DEFAULT_VIA dev $IF_A); ip -n \$NS_B route show default (empty); ip -n \$NS_B route get 8.8.8.8 (fails)  # seal assertions, autodetect stand"
else
  note_cmd "ip -n \$NS route show default (empty); ip -n \$NS route get 8.8.8.8 (fails)  # seal assertions, both namespaces"
fi
ISOLATION_MODE=autodetect; [ "$SUITE" != scan-control ] || ISOLATION_MODE=scan-control
[ "$SUITE" != ipv6 ] || ISOLATION_MODE=ipv6
[ "$SUITE" != ipv6 ] || note_cmd "ip -n \$NS_A -6 route show default (exactly: default via $IP6_GW dev $IF_A); ip -n \$NS_B -6 route show default (empty); ip -n \$NS_B -6 route get 2001:db8::1 (fails); capture isolation --mode ipv6  # seal assertions, ipv6 stand"
"$LAB_BIN" capture isolation ${DEFAULT_VIA:+--mode $ISOLATION_MODE} --out "$OUT/isolation.json" --ns-a "$NS_A" --ns-b "$NS_B" --host-links-before "$WORK/host-links-before.txt"

topo() {  # topo FILE : save topology + routes of both namespaces
  { echo "# host namespace links (must not contain veth-a/veth-b)"; ip -o link | awk -F': ' '{print $2}'
    for ns in "$NS_A" "$NS_B"; do
      echo; echo "# ===== namespace $ns ====="
      echo "## ip -d link"; ip -n "$ns" -d link show
      echo "## ip -4 addr"; ip -n "$ns" -4 addr show
      echo "## ip route"; ip -n "$ns" route show
      echo "## ip -6 route"; ip -n "$ns" -6 route show
      if [ "$SUITE" = ipv6 ]; then
        echo "## ip -6 addr"; ip -n "$ns" -6 addr show
        echo "## ip -6 neigh"; ip -n "$ns" -6 neigh show
      fi
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
  if [ "$STAND_SUITE" = 1 ]; then
    note_cmd "(rmasscan-lab $SUITE-suite) ip netns exec \$NS_B rmasscan-lab capture responder --ports $OPEN_PORTS ...   # started by the suite"
  else
    note_cmd "(rmasscan-lab wire-suite) ip netns exec \$NS_B rmasscan-lab capture responder --ports $OPEN_PORTS ...   # restarted before every run"
  fi
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
  hang) log "injected hang"; start_bg "$WORK/hang.log" sleep 600; wait "$BGPID" ;;
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

if [ "$SUITE" = autodetect ]; then
  # ---- autodetect suite: the Rust driver runs inside this sealed lab and starts its own responders/witnesses
  note_cmd "rmasscan-lab autodetect-suite linux ...   # runs everything through ip netns exec \$NS_A / \$NS_B"
  start_suite_group "$OUT/suite.log" "$LAB_BIN" autodetect-suite linux --out "$OUT" --work "$WORK" \
    --ns-a "$NS_A" --ns-b "$NS_B" --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" \
    --rmasscan "$RMASSCAN_BIN" --oracle "$ORACLE" --conf-masked "$CONF_MASKED" --lab-id "$LAB_ID"
  SUITE_PID=$SUITE_PGID
  SUITE_RC=0; wait "$SUITE_PID" || SUITE_RC=$?
  stop_suite_group
  log "suite $SUITE finished rc=$SUITE_RC (see $OUT/suite.log)"
elif [ "$SUITE" = output ]; then
  # ---- output suite: the same driver on the same stand, every output format of the C oracle and rmasscan
  note_cmd "rmasscan-lab output-suite linux ...   # runs everything through ip netns exec \$NS_A / \$NS_B"
  start_suite_group "$OUT/suite.log" "$LAB_BIN" output-suite linux --out "$OUT" --work "$WORK" \
    --ns-a "$NS_A" --ns-b "$NS_B" --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" \
    --rmasscan "$RMASSCAN_BIN" --oracle "$ORACLE" --conf-masked "$CONF_MASKED" --lab-id "$LAB_ID"
  SUITE_PID=$SUITE_PGID
  SUITE_RC=0; wait "$SUITE_PID" || SUITE_RC=$?
  stop_suite_group
  log "suite $SUITE finished rc=$SUITE_RC (see $OUT/suite.log)"
elif [ "$SUITE" = scan-control ]; then
  # ---- scan-control suite: the same driver on the same stand plus the second pair, for --adapter[1]
  note_cmd "rmasscan-lab scan-control-suite linux ...   # runs everything through ip netns exec \$NS_A / \$NS_B"
  start_suite_group "$OUT/suite.log" "$LAB_BIN" scan-control-suite linux --out "$OUT" --work "$WORK" \
    --ns-a "$NS_A" --ns-b "$NS_B" --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" \
    --rmasscan "$RMASSCAN_BIN" --oracle "$ORACLE" --conf-masked "$CONF_MASKED" --lab-id "$LAB_ID"
  SUITE_PID=$SUITE_PGID
  SUITE_RC=0; wait "$SUITE_PID" || SUITE_RC=$?
  stop_suite_group
  log "suite $SUITE finished rc=$SUITE_RC (see $OUT/suite.log)"
elif [ "$SUITE" = protocols ]; then
  # ---- protocols suite: the same driver on the same stand, ICMP Echo, UDP, SCTP and ARP of the C oracle and rmasscan
  note_cmd "rmasscan-lab protocols-suite linux ...   # runs everything through ip netns exec \$NS_A / \$NS_B"
  start_suite_group "$OUT/suite.log" "$LAB_BIN" protocols-suite linux --out "$OUT" --work "$WORK" \
    --ns-a "$NS_A" --ns-b "$NS_B" --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" \
    --rmasscan "$RMASSCAN_BIN" --oracle "$ORACLE" --conf-masked "$CONF_MASKED" --lab-id "$LAB_ID"
  SUITE_PID=$SUITE_PGID
  SUITE_RC=0; wait "$SUITE_PID" || SUITE_RC=$?
  stop_suite_group
  log "suite $SUITE finished rc=$SUITE_RC (see $OUT/suite.log)"
elif [ "$SUITE" = ipv6 ]; then
  # ---- ipv6 suite: the same driver on the same stand with IPv6 on its veth pair, TCP SYN over IPv6 of both scanners
  note_cmd "rmasscan-lab ipv6-suite linux ...   # runs everything through ip netns exec \$NS_A / \$NS_B"
  start_suite_group "$OUT/suite.log" "$LAB_BIN" ipv6-suite linux --out "$OUT" --work "$WORK" \
    --ns-a "$NS_A" --ns-b "$NS_B" --iface-a "$IF_A" --iface-b "$IF_B" --mac-a "$MAC_A" --mac-b "$MAC_B" \
    --rmasscan "$RMASSCAN_BIN" --oracle "$ORACLE" --conf-masked "$CONF_MASKED" --lab-id "$LAB_ID"
  SUITE_PID=$SUITE_PGID
  SUITE_RC=0; wait "$SUITE_PID" || SUITE_RC=$?
  stop_suite_group
  log "suite $SUITE finished rc=$SUITE_RC (see $OUT/suite.log)"
elif [ "$SUITE" != oracle ]; then
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
elif [ "$STAND_SUITE" = 1 ]; then
  log "done: $OUT"
  exit "${SUITE_RC:-0}"
else
  log "done: $OUT/results.json"
  exit "${SUITE_RC:-0}"
fi
