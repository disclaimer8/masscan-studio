#!/bin/bash
# Orchestrator on home-pc for ONE raw run of the Npcap spike (stage 2B-Windows, task 2).
#   orch.sh <tag> <test> <cond> [flood-pps]
# cond: idle | flood | down | overflow | unplug | none
# Mandatory per-run conditions: guest Verify + record-guest + full status (raw_run_allowed:true) BEFORE;
# captures on peer lab0 AND home-pc eno1 (eno1 must stay at 0 lab packets); status again AFTER.
set -u
TAG=${1:?tag}; TEST=${2:?test}; COND=${3:?cond}; PPS=${4:-20000}
SHA=${SHA:?set SHA}
LAB=$HOME/winvm/lab; MAN=$LAB/n2.json; PY="python3 $LAB/windows-vm-lab.py --run-id n2 --manifest $MAN"
TOOLS=$HOME/winvm/spike-tools
EV=$HOME/winvm/spike-ev/$TAG; mkdir -p "$EV"
G="ssh -o BatchMode=yes -p 2222 lab@127.0.0.1"
NS=wvp-n2; TAP=wvt-n2
GUEST_MAC=52:54:00:04:80:a9; PEER_MAC=02:57:4c:3d:2e:9b
log() { echo "[$(date -u +%FT%T.%3NZ)] $*" | tee -a "$EV/orch.log"; }
TAPTOUCHED=0
restore_tap() { [ "$TAPTOUCHED" = 1 ] && sudo -n ip link set $TAP up 2>/dev/null; }
trap restore_tap EXIT

# ---- 1. mandatory pre-run checks
log "tag=$TAG test=$TEST cond=$COND sha=$SHA"
$G 'cd C:\Users\lab && pwsh -NoProfile -File windows-vm-lab.ps1 -Manifest n2.json -Action Verify' > "$EV/guest-verify.stdout.json" 2> "$EV/guest-verify.stderr" || { log "STOP: guest Verify failed"; exit 10; }
scp -q -o BatchMode=yes -P 2222 'lab@127.0.0.1:n2.json.verify.json' "$EV/guest-verify.json" || exit 10
$PY record-guest --verify-json "$EV/guest-verify.json" > "$EV/record-guest.json" || { log "STOP: record-guest failed"; exit 11; }
$PY status > "$EV/status-pre.json"; rc=$?
cat "$EV/status-pre.json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("raw_run_allowed", d["raw_run_allowed"], "violations", d["isolation_violations"])' | tee -a "$EV/orch.log"
python3 - "$EV/status-pre.json" <<'PY' || { log "STOP: status says raw run not allowed"; exit 12; }
import json,sys
d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("raw_run_allowed") is True else 1)
PY

# ---- 2. captures (exact filters recorded)
PEER_FILTER='not ether proto 0x88b5'
ENO1_FILTER="net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host $GUEST_MAC or ether host $PEER_MAC or ether proto 0x88b5"
echo "peer_all:   sudo ip netns exec $NS tcpdump -i lab0 -n -U -s 96 -w peer.pcap '$PEER_FILTER'" > "$EV/capture-filters.txt"
echo "peer_junk:  sudo ip netns exec $NS tcpdump -i lab0 -n -U -w /dev/null 'ether proto 0x88b5'  (count only)" >> "$EV/capture-filters.txt"
echo "eno1:       sudo tcpdump -i eno1 -n -U -s 96 -w eno1.pcap '$ENO1_FILTER'" >> "$EV/capture-filters.txt"
startcap() { # name, command... ; pid file holds the real pid of the exec()ed command (bash exec keeps the pid)
  local name=$1; shift
  sudo -n bash -c 'echo $$ > "$0"; exec "$@"' "$EV/$name.pid" "$@" > "$EV/$name.out" 2> "$EV/$name.err" &
}
stopcap() { [ -s "$EV/$1.pid" ] && sudo -n kill -INT "$(cat "$EV/$1.pid")" 2>/dev/null; }
startcap peer ip netns exec $NS tcpdump -i lab0 -n -U -s 96 -w "$EV/peer.pcap" "$PEER_FILTER"
startcap peerjunk ip netns exec $NS tcpdump -i lab0 -n -U -w /dev/null 'ether proto 0x88b5'
startcap eno1 tcpdump -i eno1 -n -U -s 96 -w "$EV/eno1.pcap" "$ENO1_FILTER"
sleep 2
stopcaps() { stopcap peer; stopcap peerjunk; stopcap eno1; sleep 2; }

# ---- 3. condition
EXTRA="RMASSCAN_NPCAP_NOP=1"; SAMPLE=""
FLOODPID=""; NOW=$(date +%s)
case $COND in
  idle|none) ;;
  flood)
    startcap flood ip netns exec $NS python3 $TOOLS/flood.py --pps "$PPS" --duration 75 --out "$EV/flood.json"; FLOODPID=1; sleep 2 ;;
  down)
    TAPTOUCHED=1; sudo -n ip link set $TAP down; log "tap $TAP DOWN"; sleep 3
    ( $G 'pwsh -NoProfile -Command "(Get-NetAdapter -Name \"Ethernet 2\").Status"' ) > "$EV/guest-nic-status-while-down.txt" 2>&1 ;;
  overflow)
    START=$((NOW+18)); EXTRA="RMASSCAN_NPCAP_START_AT=${START}000,RMASSCAN_NPCAP_HOLD_MS=${HOLD_MS:-6000},RMASSCAN_NPCAP_SMALL_BUF=${SMALL_BUF:-32768}"
    startcap flood ip netns exec $NS python3 $TOOLS/flood.py --count "${COUNT:-200000}" --pps "${PPS_OVF:-0}" --start-at "$((START)).8" --out "$EV/flood.json"; FLOODPID=1 ;;
  unplug)
    START=$((NOW+18)); DOWN=$((START+8)); UP=$((START+18))
    EXTRA="RMASSCAN_NPCAP_START_AT=${START}000,RMASSCAN_NPCAP_DOWN_AT=${DOWN}000,RMASSCAN_NPCAP_UP_AT=${UP}000,RMASSCAN_NPCAP_TOTAL_MS=30000"
    SAMPLE="-SampleStatus"; TAPTOUCHED=1
    ( while [ $(date +%s) -lt $DOWN ]; do sleep 0.05; done
      sudo -n ip link set $TAP down; echo "$(date +%s.%N) tap DOWN" >> "$EV/tap-events.txt"
      while [ $(date +%s) -lt $UP ]; do sleep 0.05; done
      sudo -n ip link set $TAP up; echo "$(date +%s.%N) tap UP" >> "$EV/tap-events.txt" ) &
    TAPPID=$!
    if [ "${UNPLUG_FLOOD:-0}" = 1 ]; then
      startcap flood ip netns exec $NS python3 $TOOLS/flood.py --pps "$PPS" --duration 40 --start-at "$START" --out "$EV/flood.json"; FLOODPID=1
    fi ;;
esac
[ -n "${EXTRA_ENV:-}" ] && EXTRA="$EXTRA,$EXTRA_ENV"

# ---- 4. the guest run
log "guest run begins"
timeout ${RUN_TIMEOUT:-420} $G "pwsh -NoProfile -File C:\\Users\\lab\\spike\\run_live.ps1 -Tag $TAG -Test $TEST -Cond $COND -Sha $SHA -Extra $EXTRA $SAMPLE" > "$EV/guest-run.stdout" 2> "$EV/guest-run.stderr"
GRC=$?
log "guest run ended rc=$GRC"
if [ $GRC = 124 ]; then log "TIMEOUT: killing leftover guest test processes"; $G 'taskkill /f /im rmasscan_net*' >> "$EV/orch.log" 2>&1; fi

# ---- 5. teardown
[ -n "$FLOODPID" ] && { stopcap flood; sleep 1; }
[ "${TAPPID:-}" ] && wait $TAPPID 2>/dev/null
if [ "$TAPTOUCHED" = 1 ]; then restore_tap; log "tap $TAP UP (restored)"; fi
sleep 2
stopcaps
scp -q -r -o BatchMode=yes -P 2222 "lab@127.0.0.1:spike/out/$TAG/." "$EV/guest-out/" 2>/dev/null || { mkdir -p "$EV/guest-out"; scp -q -r -o BatchMode=yes -P 2222 "lab@127.0.0.1:spike/out/$TAG/*" "$EV/guest-out/"; }

# ---- 6. post checks + hashes
for f in peer eno1; do
  n=$(tcpdump -nr "$EV/$f.pcap" 2>/dev/null | wc -l); echo "$f.pcap frames=$n" | tee -a "$EV/orch.log"
done
tail -n 3 "$EV/peer.err" "$EV/peerjunk.err" "$EV/eno1.err" 2>/dev/null | tee -a "$EV/orch.log"
$PY status > "$EV/status-post.json"; python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("post raw_run_allowed", d["raw_run_allowed"], "violations", d["isolation_violations"])' "$EV/status-post.json" | tee -a "$EV/orch.log"
( cd "$EV" && sha256sum *.pcap > pcap.sha256 2>/dev/null; ls -l *.pcap > pcap.sizes 2>/dev/null )
exit $GRC
