# Perm re-check, recheck-perm (rmasscan-lab 931f69f)

`windows-suite --suite recheck-perm --plan failure --only perm_restricted_scan perm_restricted_inventory perm_elevated_control`, 2026-10-25 04:16 to 04:29 WEST (about 13 min), exit 0, no abort.
Verdict: overall NOT RUN by design (the other 15 planned runs are absent): `{"FAIL":0,"INVALID":0,"NOT RUN":15,"PASS":4}`. `windows-verify` exit 2.
- `perm_restricted_scan`: PASS. Guest exit 5, error `PermissionDenied` with "only loopback is visible: Npcap may be installed in Administrators-only mode and this process lacks rights (1 devices enumerated)", `opened_adapter=false`, `tx_sent=0`, no scanner SYN on the peer capture (6 marker frames only). `manifest.json` carries `"perm_restricted_refusal": "PermissionDenied"`.
- `perm_restricted_inventory`: PASS, guest exit 5 (loopback only, access_hint set).
- `perm_elevated_control`: PASS, guest exit 0, 1 SYN sent.
- eno1: 0 lab frames in all three runs (every eno1.pcap is the 24-byte header).
Provenance: see ../README.md. The repository copy has `/home/a1` replaced by `$HOME` in text files; pcaps untouched; verdict.json regenerated on this copy (same verdicts). The stored deploy-manifest.json therefore hashes to 74211b54...1633; `sed 's#\$HOME#/home/a1#g'` reproduces the recorded 6303cd69e5d15bbb1b7a161c9f433f18dfbfbbb9ab28703b1764543d5ab714e8.
Preflight clock uncertainty 3.29 s.
Note: the restricted runs' own `identity` still prints `elevated: true, restricted_token: false` although `runas /trustlevel:0x20000` denied the device; the verifier records these flags only as notes.
