# smoke-628fcad

Two sub-directories, each its own suite directory: `functional/` (`--plan functional --only c01_one_addr_port_synack.run1`) and `perf/` (`--plan perf --only perf.100.r1`). Overall NOT RUN by design in both (only one run planned). Guest unit tests: see `../verification/` (`guest-test-net-628fcad-first.log`: `cargo test --locked -p rmasscan-net` 168 + other targets pass, 0 failed).
