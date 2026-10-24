#!/usr/bin/env bash
# sealed throwaway lab for linux_io ignored tests: own namespaces only
set -uo pipefail
cd ~/rmasscan-t4-accept/rmasscan
source ~/.cargo/env 2>/dev/null
BIN=$(cargo test --locked -p rmasscan-net --test linux_io --no-run --message-format=json 2>/dev/null | python3 -c "
import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except: continue
    if m.get('executable') and m.get('target',{}).get('name')=='linux_io': print(m['executable'])")
echo "bin=$BIN sha=$(sha256sum $BIN | cut -d' ' -f1)"
ID=$$; A=t4io-a-$ID; B=t4io-b-$ID
cleanup(){ sudo -n ip netns del $A 2>/dev/null; sudo -n ip netns del $B 2>/dev/null; echo "namespaces_left=$(ip netns list | grep -c t4io-.*-$ID)"; }
trap cleanup EXIT
sudo -n ip netns add $A; sudo -n ip netns add $B
sudo -n ip -n $A link add veth-a type veth peer name veth-b netns $B
sudo -n ip -n $A link set veth-a address 02:aa:00:00:00:01; sudo -n ip -n $B link set veth-b address 02:aa:00:00:00:02
sudo -n ip -n $A link set veth-a up; sudo -n ip -n $B link set veth-b up
sudo -n ip -n $A link set lo up
ENVV="RMASSCAN_LAB_IFACE=veth-a RMASSCAN_LAB_IP=10.200.0.100 RMASSCAN_LAB_MAC=02:aa:00:00:00:01 RMASSCAN_LAB_PEER_MAC=02:aa:00:00:00:02"
: export RMASSCAN_LAB_IFACE=veth-a RMASSCAN_LAB_IP=10.200.0.100 RMASSCAN_LAB_MAC=02:aa:00:00:00:01 RMASSCAN_LAB_PEER_MAC=02:aa:00:00:00:02
echo "== privileged lab tests (root in ns)"
sudo -n ip netns exec $A env $ENVV "$BIN" --ignored --skip without_privilege --test-threads=1 2>&1 | grep -E "^test |test result|panicked"
echo "== unprivileged test (nobody in ns)"
sudo -n ip netns exec $A env $ENVV setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all "$BIN" --ignored lab_open_without_privilege 2>&1 | grep -E "^test |test result"
