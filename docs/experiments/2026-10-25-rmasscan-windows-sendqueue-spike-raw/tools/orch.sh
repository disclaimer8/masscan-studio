#!/bin/bash
# Orchestrator on home-pc for ONE raw run of the sendqueue spike (Task 3).
#   SHA=<7-hex build dir suffix> orch.sh <tag> <test> <cond> [extra-env k=v;k=v]
# cond: idle | flood | linkloss
# Mandatory per-run conditions: guest Verify with nonce + record-guest + full status (raw_run_allowed:true,
# matching nonce) BEFORE; captures on peer lab0 AND home-pc eno1 (eno1 must stay at 0 lab frames, else exit 13);
# full status again AFTER; sha256 of every artefact on home-pc BEFORE it is copied anywhere.
set -u
TAG=${1:?tag}; TEST=${2:?test}; COND=${3:?cond}; EXTRA=${4:-}
SHA=${SHA:?set SHA}
LAB=$HOME/winvm/lab; BIN=$LAB/bin/rmasscan-lab; MAN=$LAB/n2.json; QMP=$HOME/winvm/qmp.sock
EV=$HOME/winvm/sq-ev/$TAG; mkdir -p "$EV"
G="ssh -o BatchMode=yes -p 2222 lab@127.0.0.1"
NS=wvp-n2
GUEST_MAC=52:54:00:04:80:a9; PEER_MAC=02:57:4c:3d:2e:9b
FLOOD_PPS=${FLOOD_PPS:-20000}; FLOOD_DUR=${FLOOD_DUR:-200}
RUN_TIMEOUT=${RUN_TIMEOUT:-600}
log() { echo "[$(date -u +%FT%T.%3NZ)] $*" | tee -a "$EV/orch.log"; }
status() { sudo -n "$BIN" vm-lab status --run-id n2 --manifest "$MAN"; }
raw_ok() { grep -qF '"raw_run_allowed":true' "$1" && grep -qF '"isolation_violations":[]' "$1"; }
nonce_is() { grep -qF "\"guest_verify_nonce\":\"$2\"" "$1"; }

# ---- 1. mandatory pre-run checks
NONCE="r$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RPT="C:\\Users\\lab\\t4\\in\\sq.$TAG.$NONCE.verify.json"
log "tag=$TAG test=$TEST cond=$COND sha=$SHA nonce=$NONCE extra=$EXTRA"
$G "pwsh -NoProfile -File C:\\Users\\lab\\windows-vm-lab.ps1 -Manifest C:\\Users\\lab\\n2.json -Action Verify -VerificationNonce $NONCE -ReportPath $RPT" \
    > "$EV/guest-verify.stdout.json" 2> "$EV/guest-verify.stderr" || { log "STOP: guest Verify failed"; exit 10; }
scp -q -o BatchMode=yes -P 2222 "lab@127.0.0.1:t4/in/sq.$TAG.$NONCE.verify.json" "$EV/guest-verify.json" || { log "STOP: cannot fetch Verify report"; exit 10; }
sudo -n "$BIN" vm-lab record-guest --run-id n2 --manifest "$MAN" --verify-json "$EV/guest-verify.json" --nonce "$NONCE" \
    > "$EV/record-guest.json" 2> "$EV/record-guest.err" || { log "STOP: record-guest failed"; exit 11; }
status > "$EV/status-pre.json"
raw_ok "$EV/status-pre.json" || { log "STOP: status says raw run not allowed"; exit 12; }
nonce_is "$EV/status-pre.json" "$NONCE" || { log "STOP: status relied on another Verify"; exit 12; }
log "pre status ok (raw_run_allowed true, nonce matches)"

# ---- 2. captures (exact commands recorded)
PEER_FILTER="ether src $GUEST_MAC"
ENO1_FILTER="net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host $GUEST_MAC or ether host $PEER_MAC or ether proto 0x88b5 or ether proto 0x88b6"
{
  echo "peer: sudo ip netns exec $NS tcpdump -i lab0 -n -U --immediate-mode -B 65536 -s 96 -Z root -w peer.pcap '$PEER_FILTER'"
  echo "eno1: sudo tcpdump -i eno1 -n -U --immediate-mode -B 4096 -s 0 -Z root -w eno1.pcap '$ENO1_FILTER'"
} > "$EV/capture-filters.txt"
startbg() { # name, command... ; pid file holds the pid of the exec()ed command (a dead-man timeout wraps it)
  local name=$1; shift
  nohup sudo -n bash -c 'echo $$ > "$0"; exec timeout '"$RUN_TIMEOUT"' "$@"' "$EV/$name.pid" "$@" > "$EV/$name.out" 2> "$EV/$name.err" < /dev/null &
}
sigbg() { [ -s "$EV/$1.pid" ] && sudo -n kill -"$2" "$(cat "$EV/$1.pid")" 2>/dev/null; }
alive() { [ -s "$EV/$1.pid" ] && sudo -n kill -0 "$(cat "$EV/$1.pid")" 2>/dev/null; }
waitgone() { local i=0; while alive "$1" && [ $i -lt "${2:-40}" ]; do sleep 0.5; i=$((i+1)); done; }
cleanup() { touch "$EV/linkloss.stop"; for n in flood linkloss peer eno1; do sigbg $n TERM; done; sigbg peer INT; sigbg eno1 INT; }
trap cleanup EXIT
startbg peer ip netns exec $NS tcpdump -i lab0 -n -U --immediate-mode -B 65536 -s 96 -Z root -w "$EV/peer.pcap" "$PEER_FILTER"
startbg eno1 tcpdump -i eno1 -n -U --immediate-mode -B 4096 -s 0 -Z root -w "$EV/eno1.pcap" "$ENO1_FILTER"
for i in $(seq 1 40); do grep -q 'listening on' "$EV/peer.err" 2>/dev/null && grep -q 'listening on' "$EV/eno1.err" 2>/dev/null && break; sleep 0.5; done
grep -q 'listening on' "$EV/peer.err" && grep -q 'listening on' "$EV/eno1.err" || { log "STOP: captures did not start"; exit 14; }

# ---- 3. condition
case $COND in
  idle) ;;
  flood)
    startbg flood ip netns exec $NS "$BIN" peer flood --guest-mac $GUEST_MAC --pps "$FLOOD_PPS" --size 60 --duration "$FLOOD_DUR" --out "$EV/flood.json"
    sleep 3; alive flood || { log "STOP: flood did not start"; exit 15; } ;;
  linkloss)
    startbg linkloss ip netns exec $NS "$BIN" peer linkloss --guest-mac $GUEST_MAC --sock "$QMP" --down-after 2.0 --hold-max ${HOLD_MAX:-60} --wait-first 120 --stop-file "$EV/linkloss.stop" --out "$EV/linkloss.json"
    sleep 1 ;;
  *) log "bad cond"; exit 2 ;;
esac

# ---- 4. the guest run
SAMPLE=""; [ "$COND" = linkloss ] && SAMPLE="-SampleStatus"
log "guest run begins"
timeout "$RUN_TIMEOUT" $G "pwsh -NoProfile -File C:\\Users\\lab\\spike\\run_live_sq.ps1 -Tag $TAG -Test $TEST -Cond $COND -Sha $SHA -Extra \"$EXTRA\" $SAMPLE" > "$EV/guest-run.stdout" 2> "$EV/guest-run.stderr"
GRC=$?
log "guest run ended rc=$GRC"
if [ $GRC = 124 ]; then log "TIMEOUT: killing leftover guest test processes"; $G 'taskkill /f /im rmasscan_net*' >> "$EV/orch.log" 2>&1; fi

# ---- 5. teardown
if [ "$COND" = flood ]; then sigbg flood TERM; waitgone flood 40; fi
if [ "$COND" = linkloss ]; then
  touch "$EV/linkloss.stop"; waitgone linkloss 120
  for i in $(seq 1 60); do status > "$EV/status-link-restored.json"; raw_ok "$EV/status-link-restored.json" && break; sleep 1; done
  raw_ok "$EV/status-link-restored.json" && log "link restored, raw_run_allowed true" || log "WARNING: link not restored"
fi
sleep 2
sigbg peer INT; sigbg eno1 INT; waitgone peer 20; waitgone eno1 20
trap - EXIT
status > "$EV/status-post.json"
raw_ok "$EV/status-post.json" && log "post status ok (raw_run_allowed true)" || log "WARNING: post status not ok"

# ---- 6. frame counts and hashes (before any copy)
N_ENO1=$(tcpdump -nr "$EV/eno1.pcap" 2>/dev/null | wc -l)
N_PEER=$(tcpdump -nr "$EV/peer.pcap" 2>/dev/null | wc -l)
echo "eno1.pcap lab_frames=$N_ENO1" | tee -a "$EV/orch.log"
echo "peer.pcap frames=$N_PEER" | tee -a "$EV/orch.log"
tail -n 3 "$EV/peer.err" "$EV/eno1.err" 2>/dev/null | tee -a "$EV/orch.log"
scp -q -r -o BatchMode=yes -P 2222 "lab@127.0.0.1:spike/sq/$TAG/." "$EV/guest-out/" 2>/dev/null || { mkdir -p "$EV/guest-out"; scp -q -r -o BatchMode=yes -P 2222 "lab@127.0.0.1:spike/sq/$TAG/*" "$EV/guest-out/"; }
rm -f "${EV:?}"/*.pid
( cd "$EV" && ls -l ./*.pcap > pcap.sizes; find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS )
echo "$GRC" > "$EV/guest-rc.txt"
if [ "$N_ENO1" != 0 ]; then log "STOP: $N_ENO1 lab frame(s) on eno1"; exit 13; fi
exit $GRC
