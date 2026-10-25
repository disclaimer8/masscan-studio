#!/bin/bash
# usage: run.sh OUTNAME SUITE PLAN [extra args]
S=$SCRATCH
cd $S/live-win3/repo
OUT=$1; SUITE=$2; PLAN=$3; shift 3
$S/live-win3/bin/rmasscan-lab windows-suite --out $S/live-win3/ev/$OUT --suite $SUITE --plan $PLAN \
  --commit 931f69fd1eaa0affd160d047b39855843c8cb152 --repo . --guest-exe 'C:\Users\lab\t4\wire_scan.exe' \
  --fixtures docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures \
  --remote-lab $HOME/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json "$@"
echo "EXIT=$?"
