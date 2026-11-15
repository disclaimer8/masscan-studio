#!/usr/bin/env zsh
# Post-fix fuzz runs of the stack family (release lab built from the post-fix commit, commit.txt, clean tree), from the checkout root (corpus path
# relative to it), same corpus and captures as Task 19: (1) the seed-413 reproducer over exactly Task 19's 29093011 inputs (its inputs_sha256 must match),
# (2) a fresh seed for 3700 s. Both under nice -n 19.
trap 'trap - EXIT INT TERM; kill 0' EXIT INT TERM
F=/private/tmp/rmasscan-postfix-fuzz.WizuTr
PCAPDIR=$F/pcaps  # the 29 peer.pcap of linux-banners-r1 (Task 19), copied from the committed raw evidence, sha256 checked against its MANIFEST
cd /private/tmp/rmasscan-final-4b
PCAPS=($PCAPDIR/linux-banners-r1/runs/*/*/peer.pcap)
print -r -- "start $(date -u +%FT%TZ) pcaps ${#PCAPS}" > $F/start.txt
( nice -n 19 $F/bin/rmasscan-lab fuzz tcp --family stack --seed 413 --count 29093011 \
    --corpus rmasscan/tests/golden/tcp-banners --pcap $PCAPS \
    --out $F/repro-stack-413-count-29093011.json > $F/repro-stack-413.log 2>&1; echo $? > $F/repro-stack-413.rc; print -r -- "repro end $(date -u +%FT%TZ)" >> $F/start.txt ) &
( nice -n 19 $F/bin/rmasscan-lab fuzz tcp --family stack --seed 1511202619 --duration 3700 \
    --corpus rmasscan/tests/golden/tcp-banners --pcap $PCAPS \
    --out $F/fuzz-tcp-stack-1511202619.json > $F/fuzz-tcp-stack-1511202619.log 2>&1; echo $? > $F/fuzz-tcp-stack-1511202619.rc; print -r -- "fuzz end $(date -u +%FT%TZ)" >> $F/start.txt ) &
wait
print -r -- "end $(date -u +%FT%TZ)" >> $F/start.txt
trap - EXIT INT TERM
