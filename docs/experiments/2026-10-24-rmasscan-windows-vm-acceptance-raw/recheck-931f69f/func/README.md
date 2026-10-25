# Functional re-check, recheck-func (rmasscan-lab 931f69f)

`windows-suite --suite recheck-func --plan functional --only c01_one_addr_port_synack.run1`, 2026-10-25 04:29:58 to 04:35:23 WEST (about 5.4 min), exit 0, no abort.
Verdict: run PASS, overall NOT RUN by design: `{"FAIL":0,"INVALID":0,"NOT RUN":27,"PASS":2}` (manifest + run). 1 SYN, identical to the C oracle fixture ("SYN bytes and order equal C oracle", "oracle fixture binding identical without normalization"). eno1: 0 lab frames (24-byte pcap).
During this run a second `windows-suite --cleanup --suite recheck-func` was started from another shell at 04:30:47: refused in 3 s, exit 2, "NOT RUN: another windows-suite invocation (or --cleanup) holds ~/winvm/t4-ev/.suite.lock on home-pc; run one suite at a time. Nothing was changed."; the running suite was not disturbed.
Text scrub, verdict regeneration and deploy-manifest hash as in ../perm/README.md. Preflight clock uncertainty 3.36 s.
