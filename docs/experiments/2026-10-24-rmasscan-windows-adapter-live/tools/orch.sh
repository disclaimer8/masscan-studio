#!/bin/bash
# Orchestrator on home-pc for ONE raw run of a Windows-adapter live test (stage 2B-Windows, task 3).
#   SHA=<sha7> orch.sh <tag> <bin: rmasscan_net|windows_live> <test> <cond>
# cond: plain | flood | linkloss
# Mandatory per-run conditions: guest Verify + record-guest + full status (raw_run_allowed:true) BEFORE;
# captures on the peer (lab0) AND home-pc eno1 (eno1 must stay at 0 lab packets); status again AFTER.
# linkloss: QMP set_link on netdev lab0 (VM-local, reversible; restored by trap even on failure).
set -u
TAG=${1:?tag}; BIN=${2:?bin}; TEST=${3:?test}; COND=${4:?cond}
SHA=${SHA:?set SHA}
LAB=$HOME/winvm/lab; MAN=$LAB/n2.json; PY="python3 $LAB/windows-vm-lab.py --run-id n2 --manifest $MAN"
TOOLS=${TOOLS:-$HOME/winvm/t3-tools}
EV=$HOME/winvm/t3-ev/$TAG; mkdir -p "$EV"
G="ssh -o BatchMode=yes -p 2222 lab@127.0.0.1"
NS=wvp-n2
GUEST_MAC=52:54:00:04:80:a9; PEER_MAC=02:57:4c:3d:2e:9b
log() { echo "[$(date -u +%FT%T.%3NZ)] $*" | tee -a "$EV/orch.log"; }
LINKTOUCHED=0
restore_link() { if [ "$LINKTOUCHED" = 1 ]; then python3 $TOOLS/qmp_link.py up >> "$EV/qmp-events.txt" 2>&1; LINKTOUCHED=0; fi; }
trap restore_link EXIT

# ---- 1. mandatory pre-run checks
log "tag=$TAG bin=$BIN test=$TEST cond=$COND sha=$SHA"
$G 'cd C:\Users\lab && pwsh -NoProfile -File windows-vm-lab.ps1 -Manifest n2.json -Action Verify' > "$EV/guest-verify.stdout.json" 2> "$EV/guest-verify.stderr" || { log "STOP: guest Verify failed"; exit 10; }
scp -q -o BatchMode=yes -P 2222 'lab@127.0.0.1:n2.json.verify.json' "$EV/guest-verify.json" || exit 10
$PY record-guest --verify-json "$EV/guest-verify.json" > "$EV/record-guest.json" || { log "STOP: record-guest failed"; exit 11; }
$PY status > "$EV/status-pre.json"
python3 - "$EV/status-pre.json" <<'PY' | tee -a "$EV/orch.log" || { log "STOP: status says raw run not allowed"; exit 12; }
import json,sys
d=json.load(open(sys.argv[1])); print("raw_run_allowed", d.get("raw_run_allowed"), "violations", d.get("isolation_violations"))
sys.exit(0 if d.get("raw_run_allowed") is True else 1)
PY

# ---- 2. captures (exact filters recorded)
PEER_FILTER='not ether proto 0x88b5'
ENO1_FILTER="net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host $GUEST_MAC or ether host $PEER_MAC or ether proto 0x88b5"
echo "peer_all:   sudo ip netns exec $NS tcpdump -i lab0 -n -U -s 96 -w peer.pcap '$PEER_FILTER'" > "$EV/capture-filters.txt"
echo "eno1:       sudo tcpdump -i eno1 -n -U -s 96 -w eno1.pcap '$ENO1_FILTER'" >> "$EV/capture-filters.txt"
startcap() { local name=$1; shift
  sudo -n bash -c 'echo $$ > "$0"; exec "$@"' "$EV/$name.pid" "$@" > "$EV/$name.out" 2> "$EV/$name.err" & }
stopcap() { [ -s "$EV/$1.pid" ] && sudo -n kill -INT "$(cat "$EV/$1.pid")" 2>/dev/null; }
startcap peer ip netns exec $NS tcpdump -i lab0 -n -U -s 96 -w "$EV/peer.pcap" "$PEER_FILTER"
startcap eno1 tcpdump -i eno1 -n -U -s 96 -w "$EV/eno1.pcap" "$ENO1_FILTER"
startcap listener ip netns exec $NS python3 $TOOLS/listener.py 8080 8081
sleep 2

# ---- 3. condition
EXTRA="RMASSCAN_NPCAP_NOP=1"; SAMPLE=""; NOW=$(date +%s)
case $COND in
  plain) ;;
  flood) startcap flood ip netns exec $NS python3 $TOOLS/flood.py --pps "${PPS:-20000}" --duration "${FLOOD_S:-60}" --out "$EV/flood.json"; sleep 2 ;;
  linkloss)
    START=$((NOW+20)); DOWN=$((START+${DOWN_OFF:-8})); UP=$((START+${UP_OFF:-18}))
    EXTRA="RMASSCAN_NPCAP_START_AT=${START}000,RMASSCAN_NPCAP_DOWN_AT=${DOWN}000,RMASSCAN_NPCAP_UP_AT=${UP}000,RMASSCAN_NPCAP_TOTAL_MS=${TOTAL_MS:-30000}"
    SAMPLE="-SampleStatus"; LINKTOUCHED=1
    ( while [ $(date +%s) -lt $DOWN ]; do sleep 0.02; done
      python3 $TOOLS/qmp_link.py down >> "$EV/qmp-events.txt" 2>&1
      while [ $(date +%s) -lt $UP ]; do sleep 0.02; done
      python3 $TOOLS/qmp_link.py up >> "$EV/qmp-events.txt" 2>&1 ) &
    TOGGLEPID=$! ;;
  *) log "bad cond"; exit 2 ;;
esac
[ -n "${EXTRA_ENV:-}" ] && EXTRA="$EXTRA,$EXTRA_ENV"

# ---- 4. the guest run
log "guest run begins ($EXTRA)"
timeout ${RUN_TIMEOUT:-300} $G "pwsh -NoProfile -File C:\\Users\\lab\\t3\\run_live.ps1 -Tag $TAG -Bin $BIN -Test $TEST -Cond $COND -Sha $SHA -Extra $EXTRA $SAMPLE" > "$EV/guest-run.stdout" 2> "$EV/guest-run.stderr"
GRC=$?
log "guest run ended rc=$GRC"
if [ $GRC = 124 ]; then log "TIMEOUT: killing leftover guest test processes"; $G "taskkill /f /im ${BIN}-*" >> "$EV/orch.log" 2>&1; fi

# ---- 5. teardown
[ -n "${TOGGLEPID:-}" ] && wait $TOGGLEPID 2>/dev/null
restore_link; [ "$COND" = linkloss ] && log "link restored (trap/explicit)"
stopcap flood; sleep 2
stopcap peer; stopcap eno1; stopcap listener; sleep 2
scp -q -r -o BatchMode=yes -P 2222 "lab@127.0.0.1:t3/out/$TAG/." "$EV/guest-out/" 2>/dev/null || { mkdir -p "$EV/guest-out"; scp -q -r -o BatchMode=yes -P 2222 "lab@127.0.0.1:t3/out/$TAG/*" "$EV/guest-out/"; }

# ---- 6. post checks + hashes
for f in peer eno1; do
  n=$(tcpdump -nr "$EV/$f.pcap" 2>/dev/null | wc -l); echo "$f.pcap frames=$n" | tee -a "$EV/orch.log"
done
syn=$(tcpdump -nr "$EV/peer.pcap" 'tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and src host 198.18.0.1 and dst host 198.18.0.2' 2>/dev/null | wc -l)
echo "peer_syn_from_guest=$syn" | tee -a "$EV/orch.log"
tail -n 3 "$EV/peer.err" "$EV/eno1.err" 2>/dev/null | tee -a "$EV/orch.log"
$PY status > "$EV/status-post.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("post raw_run_allowed", d.get("raw_run_allowed"), "violations", d.get("isolation_violations"))' "$EV/status-post.json" | tee -a "$EV/orch.log"
( cd "$EV" && sha256sum *.pcap > pcap.sha256 2>/dev/null; ls -l *.pcap > pcap.sizes 2>/dev/null )
exit $GRC
