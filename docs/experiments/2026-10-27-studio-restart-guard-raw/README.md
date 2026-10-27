# Studio restart and guard: immutable evidence

Source/build: `35b063cf943383765926fe1c417dcd8a6e36ca8d`. Mac arm64, macOS 27.0.1,
debug bundle. [Report](../2026-10-27-studio-restart-guard.md).

- `preflight-8107b89/`: prior NOT RUN gate, no children started.
- `pause-35b063c-r1/`: separate pause/exit process, PASS 2/2.
- `resume-35b063c-r1/`: new process and attempt, paired restart PASS 4/4.
- `guard-35b063c-r1/`: actual scoped ARP change and restoration, PASS 2/2.
- `verification/`: archived rechecks, build manifest, code-head CI, offline
  logs and final stand/BPF teardown observations.

Each live window retains its original `hashes-before-copy.txt`. `MANIFEST.sha256`
covers the complete archive. Mutable SQLite databases remain outside git; the
closed database hashes bind the two restart windows. No gzip files or scanners
are included. The operator's ARP readback and timestamps are hashed with the
guard window. Packet captures are the independent tcpdump witnesses, not engine
generated substitutes.

Recheck offline with the laboratory binary built from this source:

```sh
rmasscan-lab studio-verify --dir resume-35b063c-r1 --pause-dir pause-35b063c-r1 --out resume-35b063c-r1/verdict.json --expect-head 35b063cf943383765926fe1c417dcd8a6e36ca8d
rmasscan-lab studio-verify --dir guard-35b063c-r1 --out guard-35b063c-r1/verdict.json --expect-head 35b063cf943383765926fe1c417dcd8a6e36ca8d
shasum -a 256 -c MANIFEST.sha256
```

The checked-in `verification/*-recheck.json` were produced after copying the
windows into this archive. They preserve the same PASS verdicts. Physical NIC,
Windows/Linux raw, sleep and VPN behavior were not tested by these windows.
