#!/bin/bash
# Runs on the Mac after the live runs: copies one run directory from home-pc, re-checks the sha256 list that
# orch.sh took ON home-pc BEFORE the copy, trims a peer capture larger than 40 MB to its sha256, size and the
# first 2000 packets, redacts the home directory in text files, and keeps the original hash list as home-pc.sha256.
#   collect.sh <tag> <dest-runs-dir>
set -eu
TAG=${1:?tag}; DEST=${2:?dest}
LIM=$((40 * 1024 * 1024))
WORK=$(mktemp -d)
scp -q -r "home-pc:winvm/sq-ev/$TAG" "$WORK/"
cd "$WORK/$TAG"
shasum -a 256 -c SHA256SUMS > copy-verify.txt
echo "all $(grep -c ': OK' copy-verify.txt) files match the sha256 taken on home-pc before copying" >> copy-verify.txt
D="${DEST:?}/$TAG"
mkdir -p "$D"
SZ=$(stat -f %z peer.pcap)
if [ "$SZ" -gt "$LIM" ]; then
  SHA=$(shasum -a 256 peer.pcap | cut -d' ' -f1)
  N=$(tcpdump -nr peer.pcap 2> /dev/null | wc -l | tr -d ' ')
  tcpdump -r peer.pcap -c 2000 -w peer.excerpt.pcap 2> /dev/null
  printf 'peer.pcap not stored (over 40 MB). The full file stays on home-pc (~/winvm/sq-ev/%s/peer.pcap).\nsha256 %s\nsize_bytes %s\npackets %s\nstored: peer.excerpt.pcap = first 2000 packets of that capture\n' "$TAG" "$SHA" "$SZ" "$N" > peer.pcap.orig.txt
  mv peer.pcap "$WORK/$TAG.peer.pcap.full"
fi
mv SHA256SUMS home-pc.sha256
rm -f ./*.pid ./linkloss.stop
cp -R . "$D/"
RH=$(ssh home-pc 'echo $HOME')
grep -rIlF "$RH" "$D" 2> /dev/null | while read -r f; do sed -i '' "s|$RH|\$HOME|g" "$f"; done
echo "collected $TAG into $D"
