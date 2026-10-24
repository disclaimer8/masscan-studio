#!/usr/bin/env bash
# throwaway sealed lab (own namespaces only) for linux_io --ignored; records seal state
set -uo pipefail
cd ~/t4r1/rmasscan; source ~/.cargo/env
BIN=$(cargo test --locked -p rmasscan-net --test linux_io --no-run --message-format=json 2>/dev/null | python3 -c "
import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except: continue
    if m.get('executable') and m.get('target',{}).get('name')=='linux_io': print(m['executable'])")
echo "bin=$BIN sha=$(sha256sum $BIN | cut -d' ' -f1)"
ID=$$; A=t4io-a-$ID; B=t4io-b-$ID
cleanup(){ sudo -n ip netns del $A 2>/dev/null; sudo -n ip netns del $B 2>/dev/null; echo "namespaces_left=$(ip netns list | grep -c "t4io-.*-$ID")"; }
trap cleanup EXIT
sudo -n ip netns add $A; sudo -n ip netns add $B
sudo -n ip -n $A link add veth-a type veth peer name veth-b netns $B
sudo -n ip -n $A link set veth-a address 02:aa:00:00:00:01; sudo -n ip -n $B link set veth-b address 02:aa:00:00:00:02
sudo -n ip -n $A link set veth-a up; sudo -n ip -n $B link set veth-b up; sudo -n ip -n $A link set lo up
for n in $A $B; do echo "== seal $n: links"; sudo -n ip -n $n -o link | awk -F': ' '{print $2}'; echo "routes: [$(sudo -n ip -n $n route show)] default: [$(sudo -n ip -n $n route show default)]"; done
echo "host links with veth-a/b: $(ip -o link | grep -c "veth-[ab]")"
ENVV="RMASSCAN_LAB_IFACE=veth-a RMASSCAN_LAB_IP=10.200.0.100 RMASSCAN_LAB_MAC=02:aa:00:00:00:01 RMASSCAN_LAB_PEER_MAC=02:aa:00:00:00:02"
echo "== privileged lab tests, PARALLEL (default threads): observation"
sudo -n ip netns exec $A env $ENVV "$BIN" --ignored --skip without_privilege 2>&1
echo "== privileged lab tests, SERIAL (--test-threads=1)"
sudo -n ip netns exec $A env $ENVV "$BIN" --ignored --skip without_privilege --test-threads=1 2>&1
echo "== unprivileged test (uid 65534, no caps)"
sudo -n ip netns exec $A env $ENVV setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all "$BIN" --ignored lab_open_without_privilege 2>&1
