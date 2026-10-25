# macOS BPF acceptance, raw evidence (stage 2C, task 7)

| directory | part | commit / verifier | verdict |
|---|---|---|---|
| `fixtures` | C oracle SYN captures | f72115a lab build, masscan 8e6b3b0 | all_valid true |
| `functional-r1` | A | 717e45c / 2989ace | PASS 29/29 |
| `perf-r1` | C | 717e45c / 2989ace | PASS 21/21, medians 100.4 / 1014.0 / 10212.6 / 93808.6 pps |
| `failure-r1` | B | 717e45c / 2989ace | 17 PASS, 1 INVALID (`linkloss`, provisional rule) |
| `macos-live` | live adapter tests (6, `rmasscan-net/tests/macos_live.rs`) | test binary from 3e3886e | 6 passed, 0 failed; 0 uplink lab frames |

Uplink lab frames in all three suites: 0. Each directory has its own `README.md` and `MANIFEST.sha256` (`shasum -a 256`, run inside the directory: `shasum -a 256 -c MANIFEST.sha256`).
