//! Offline tests of the tcpdump witness: the completeness rules as a table, and the whole
//! start/ack/stop/finalise sequence against a scripted fake `tcpdump` (a shell script) and a
//! scripted counter probe. No root, namespaces, packets or real tcpdump. The process tests need
//! `sh` and `kill` and so run on Linux and macOS, not on Windows.
use super::*;

fn good() -> Facts {
    Facts {
        start_markers: 1,
        end_markers: 3,
        quiesced: true,
        captured: Some(100),
        received: Some(100),
        dropped_kernel: Some(0),
        dropped_if: Some(0),
        interface_drop_delta: Some(0),
        pcap_frames: 100,
        pcap_error: None,
        tcpdump_exited: true,
        window_lo: Some(98),
        window_hi: Some(101),
    }
}

#[test]
fn argv_is_packet_buffered_full_snaplen_both_directions_and_shell_free() {
    let a = tcpdump_argv("veth-b", "/w/x.pcap");
    assert_eq!(a[0], "tcpdump");
    for want in ["-U", "--immediate-mode", "--time-stamp-precision=nano"] {
        assert!(a.contains(&want.to_string()), "{want}");
    }
    let pos = |k: &str| a.iter().position(|x| x == k).unwrap();
    assert_eq!(a[pos("-i") + 1], "veth-b");
    assert_eq!(a[pos("-s") + 1], "0", "no truncation");
    assert_eq!(a[pos("-Z") + 1], "root");
    assert_eq!(a[pos("-w") + 1], "/w/x.pcap");
    assert!(!a.contains(&"-Q".to_string()), "no direction filter");
    assert!(
        a.iter().all(|x| !x.contains(' ')),
        "one argument per token, nothing for a shell to split"
    );
}

#[test]
fn a_complete_capture_has_no_problems() {
    assert!(problems(&good()).is_empty());
}

#[test]
fn every_missing_proof_makes_the_capture_invalid() {
    type Edit = fn(&mut Facts);
    let cases: [(&str, Edit, &str); 14] = [
        (
            "start marker missing",
            |f| f.start_markers = 0,
            "start marker",
        ),
        ("two end markers", |f| f.end_markers = 2, "end markers"),
        ("no end marker", |f| f.end_markers = 0, "end markers"),
        ("counters never quiet", |f| f.quiesced = false, "quiet"),
        (
            "interface drop",
            |f| f.interface_drop_delta = Some(1),
            "rx_dropped",
        ),
        (
            "interface drops unreadable",
            |f| f.interface_drop_delta = None,
            "rx_dropped",
        ),
        (
            "kernel drop",
            |f| f.dropped_kernel = Some(1),
            "completeness",
        ),
        (
            "kernel drop line missing",
            |f| f.dropped_kernel = None,
            "completeness",
        ),
        (
            "lost tail: received_by_filter > captured",
            |f| f.captured = Some(99),
            "completeness",
        ),
        (
            "pcap shorter than captured",
            |f| f.pcap_frames = 99,
            "completeness",
        ),
        (
            "below the counter window",
            |f| f.window_lo = Some(101),
            "completeness",
        ),
        (
            "above the counter window",
            |f| f.window_hi = Some(99),
            "completeness",
        ),
        (
            "counters decreased",
            |f| f.window_lo = None,
            "counters decreased",
        ),
        (
            "tcpdump did not exit",
            |f| f.tcpdump_exited = false,
            "did not exit",
        ),
    ];
    for (what, edit, needle) in cases {
        let mut f = good();
        edit(&mut f);
        let p = problems(&f);
        assert!(!p.is_empty(), "{what}: still valid");
        assert!(
            p.iter().any(|s| s.contains(needle)),
            "{what}: {p:?} lacks {needle:?}"
        );
    }
    let mut f = good();
    f.captured = None;
    f.received = None;
    f.dropped_kernel = None;
    f.dropped_if = None;
    assert!(!problems(&f).is_empty(), "tcpdump summary missing");
    let mut f = good();
    f.pcap_error = Some("truncated".into());
    assert!(problems(&f).iter().any(|s| s.contains("unreadable")));
}

#[test]
fn a_missing_interface_drop_line_falls_back_to_the_measured_delta_never_to_zero() {
    let mut f = good();
    f.dropped_if = None;
    assert!(problems(&f).is_empty(), "delta 0 stands in for the line");
    f.interface_drop_delta = None;
    assert!(!problems(&f).is_empty());
}

#[test]
fn tcpdump_statistics_are_parsed_exactly_and_garbage_stays_unknown() {
    let full = "tcpdump: listening on veth-b, link-type EN10MB\n\
        100 packets captured\n100 packets received by filter\n0 packets dropped by kernel\n2 packets dropped by interface\n";
    let s = parse_tcpdump(full);
    assert_eq!(s["listening"], true);
    assert_eq!(
        (
            s["captured"].as_u64(),
            s["received"].as_u64(),
            s["dropped_kernel"].as_u64(),
            s["dropped_if"].as_u64()
        ),
        (Some(100), Some(100), Some(0), Some(2))
    );
    // Singular forms parse; a missing "dropped by interface" line stays unknown.
    let one = parse_tcpdump(
        "1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n",
    );
    assert_eq!(one["captured"].as_u64(), Some(1));
    assert!(one["dropped_if"].is_null());
    // Garbage never becomes a number.
    let junk = parse_tcpdump(
        "x packets captured\npackets received by filter\n-3 packets dropped by kernel\n",
    );
    assert!(junk["captured"].is_null() && junk["received"].is_null());
    assert!(junk["dropped_kernel"].is_null());
    assert_eq!(parse_tcpdump("")["listening"], false);
}

#[test]
fn a_valid_witness_meta_passes_the_comparator_gate_and_an_invalid_one_does_not() {
    let mut meta = json!({"kernel_drops":0,"valid":true});
    assert!(pcap::meta_problem(&meta).is_none());
    meta["valid"] = json!(false);
    assert!(pcap::meta_problem(&meta).is_some());
    // An unmeasured kernel-drop count (null, from a missing tcpdump line) is never clean.
    assert!(pcap::meta_problem(&json!({"kernel_drops":null,"valid":true})).is_some());
}

// ---- the whole sequence against a scripted tcpdump ----

#[cfg(unix)]
mod sequence {
    use super::*;
    use crate::link::marker_frame;

    pub(super) struct Scripted {
        /// counters(): the first two calls (c0, c1) return 0, every later one `total`; when
        /// `drifting`, every call returns a new value (never quiet).
        total: u64,
        drifting: bool,
        calls: u64,
        pub(super) drops: Vec<u64>,
        ack: PathBuf,
        born: Instant,
        deadline: Duration,
        end_sent: bool,
    }
    impl Probe for Scripted {
        fn counters(&mut self) -> Result<u64, String> {
            self.calls += 1;
            if self.drifting {
                return Ok(self.calls * 10);
            }
            Ok(if self.calls <= 2 { 0 } else { self.total })
        }
        fn interface_drops(&mut self) -> Result<u64, String> {
            Ok(if self.drops.len() > 1 {
                self.drops.remove(0)
            } else {
                self.drops[0]
            })
        }
        fn send_end(&mut self) -> Result<(), String> {
            self.end_sent = true;
            Ok(())
        }
        fn stop_requested(&self) -> bool {
            self.ack.exists() || self.born.elapsed() > self.deadline
        }
    }

    pub(super) struct Rig {
        pub(super) dir: PathBuf,
        pub(super) cfg: Config,
    }
    pub(super) fn rig(tag: &str, script: &str, frames: Vec<Vec<u8>>, stats: &str) -> Rig {
        let dir = std::env::temp_dir().join(format!(
            "rmasscan-dump-{tag}-{}-{}",
            std::process::id(),
            // Random, not the time: macOS SystemTime has microsecond resolution, and
            // create_dir_all would silently let two parallel tests share one rig.
            crate::windows_suite::nonce()
        ));
        fs::create_dir(&dir).unwrap();
        let pcap = dir.join("cap.pcap");
        fs::write(
            &pcap,
            crate::pcap::encode(
                &frames
                    .into_iter()
                    .enumerate()
                    .map(|(i, f)| (i as f64, f))
                    .collect(),
            ),
        )
        .unwrap();
        let sh = dir.join("fake-tcpdump.sh");
        fs::write(&sh, script).unwrap();
        let st = dir.join("stats.txt");
        fs::write(&st, stats).unwrap();
        let cfg = Config {
            argv: vec![
                "sh".into(),
                sh.to_string_lossy().into_owned(),
                st.to_string_lossy().into_owned(),
            ],
            err: dir.join("cap.err"),
            ready: dir.join("ready"),
            ack: dir.join("ack"),
            pcap,
            start_timeout: Duration::from_secs(5),
            settle: Duration::from_millis(10),
            poll: Duration::from_millis(10),
            quiet: 0.1,
            quiet_poll: 0.02,
            quiet_timeout: 1.0,
            end_timeout: Duration::from_millis(200),
            stop_timeout: Duration::from_secs(3),
        };
        Rig { dir, cfg }
    }
    pub(super) const LISTENING: &str = "#!/bin/sh\necho 'tcpdump: listening on fake0, link-type EN10MB (Ethernet)' >&2\ntrap 'cat \"$1\" >&2; exit 0' INT\nwhile :; do sleep 0.02; done\n";
    pub(super) const DEAF: &str = "#!/bin/sh\necho 'tcpdump: listening on fake0' >&2\ntrap '' INT\nwhile :; do sleep 0.02; done\n";
    pub(super) fn stats(n: u64, kernel: u64) -> String {
        format!(
            "{n} packets captured\n{n} packets received by filter\n{kernel} packets dropped by kernel\n"
        )
    }
    fn data(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut f = vec![0u8; 60];
                f[12] = 8;
                f[13] = 0;
                f[20] = i as u8;
                f
            })
            .collect()
    }
    /// START, `n` data frames, `ends` END markers.
    fn frames(n: usize, ends: usize) -> Vec<Vec<u8>> {
        let mut v = vec![marker_frame([2; 6], [1; 6], START_PAYLOAD)];
        v.extend(data(n));
        for _ in 0..ends {
            v.push(marker_frame([1; 6], [2; 6], END_PAYLOAD));
        }
        v
    }
    pub(super) fn probe(r: &Rig, total: u64, deadline_ms: u64) -> Scripted {
        Scripted {
            total,
            drifting: false,
            calls: 0,
            drops: vec![0],
            ack: r.cfg.ack.clone(),
            born: Instant::now(),
            deadline: Duration::from_millis(deadline_ms),
            end_sent: false,
        }
    }
    pub(super) fn done(r: Rig) {
        let _ = fs::remove_dir_all(r.dir);
    }

    #[test]
    fn a_complete_capture_is_acknowledged_finalised_and_valid() {
        // 1 start + 10 data + 3 end = 14 frames; tcpdump reports 14; counters window [14,14].
        let r = rig("ok", LISTENING, frames(10, 3), &stats(14, 0));
        let mut p = probe(&r, 14, 5000);
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert_eq!(meta["valid"], true, "{meta}");
        assert!(meta["invalid_reasons"].as_array().unwrap().is_empty());
        assert_eq!(meta["start_marker_frames"], 1);
        assert_eq!(meta["end_marker_frames"], 3);
        assert_eq!(meta["pcap_frames"], 14);
        assert_eq!(meta["tcpdump_captured"], 14);
        assert_eq!(meta["kernel_drops"], 0);
        assert_eq!(meta["quiesced_before_stop"], true);
        assert!(
            r.cfg.ready.exists(),
            "ready file written once tcpdump listens"
        );
        assert!(r.cfg.ack.exists(), "start marker acknowledged");
        assert!(p.end_sent, "end markers were sent after quiescence");
        assert_eq!(meta["pcap_sha256"].as_str().unwrap().len(), 64);
        assert!(meta["tcpdump_argv"].as_array().unwrap().len() >= 3);
        assert!(crate::pcap::meta_problem(&meta).is_none());
        done(r);
    }

    #[test]
    fn missing_end_markers_make_the_tail_unproven() {
        let r = rig("noend", LISTENING, frames(10, 2), &stats(13, 0));
        let mut p = probe(&r, 13, 5000);
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert_eq!(meta["valid"], false);
        assert!(meta["invalid_reasons"].to_string().contains("end markers"));
        assert!(crate::pcap::meta_problem(&meta).is_some());
        done(r);
    }

    #[test]
    fn a_start_marker_that_never_arrives_is_never_acknowledged_and_invalid() {
        let mut fs_ = frames(10, 3);
        fs_.remove(0);
        let r = rig("nostart", LISTENING, fs_, &stats(13, 0));
        let mut p = probe(&r, 13, 400);
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert!(!r.cfg.ack.exists(), "no ack without the marker in the pcap");
        assert_eq!(meta["valid"], false);
        assert!(meta["invalid_reasons"].to_string().contains("start marker"));
        done(r);
    }

    #[test]
    fn a_lost_tail_kernel_drops_or_a_counter_gap_are_invalid() {
        // tcpdump says it captured 13 of 14 received (lost tail).
        let bad_stats =
            "13 packets captured\n14 packets received by filter\n0 packets dropped by kernel\n";
        let r = rig("tail", LISTENING, frames(10, 3), bad_stats);
        let mut p = probe(&r, 14, 5000);
        assert_eq!(witness(&r.cfg, &mut p).unwrap()["valid"], false);
        done(r);
        // A kernel drop.
        let r = rig("kdrop", LISTENING, frames(10, 3), &stats(14, 1));
        let mut p = probe(&r, 14, 5000);
        assert_eq!(witness(&r.cfg, &mut p).unwrap()["valid"], false);
        done(r);
        // The interface carried more frames than the capture holds.
        let r = rig("gap", LISTENING, frames(10, 3), &stats(14, 0));
        let mut p = probe(&r, 20, 5000);
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert_eq!(meta["valid"], false);
        assert!(meta["invalid_reasons"].to_string().contains("window"));
        done(r);
        // The interface dropped a frame.
        let r = rig("idrop", LISTENING, frames(10, 3), &stats(14, 0));
        let mut p = probe(&r, 14, 5000);
        p.drops = vec![0, 1];
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert_eq!(meta["valid"], false);
        assert!(meta["invalid_reasons"].to_string().contains("rx_dropped"));
        done(r);
    }

    #[test]
    fn endless_traffic_is_never_declared_quiet() {
        let r = rig("noisy", LISTENING, frames(10, 3), &stats(14, 0));
        let mut p = probe(&r, 14, 5000);
        p.drifting = true;
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert_eq!(meta["quiesced_before_stop"], false);
        assert_eq!(meta["valid"], false);
        done(r);
    }

    #[test]
    fn a_tcpdump_that_ignores_sigint_is_invalid_and_reaped() {
        let mut r = rig("deaf", DEAF, frames(10, 3), &stats(14, 0));
        r.cfg.stop_timeout = Duration::from_millis(300);
        let mut p = probe(&r, 14, 5000);
        let meta = witness(&r.cfg, &mut p).unwrap();
        assert_eq!(meta["valid"], false);
        assert!(meta["invalid_reasons"].to_string().contains("did not exit"));
        done(r);
    }

    #[test]
    fn tcpdump_that_never_listens_or_dies_at_startup_is_a_harness_error() {
        let mut r = rig("mute", LISTENING, frames(1, 3), &stats(5, 0));
        r.cfg.argv = vec!["sh".into(), "-c".into(), "exec sleep 5".into()];
        r.cfg.start_timeout = Duration::from_millis(300);
        let mut p = probe(&r, 0, 5000);
        let e = witness(&r.cfg, &mut p).unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert!(
            !r.cfg.ready.exists(),
            "never ready without a listening tcpdump"
        );
        done(r);
        let mut r = rig("dead", LISTENING, frames(1, 3), &stats(5, 0));
        r.cfg.argv = vec!["sh".into(), "-c".into(), "echo boom >&2; exit 3".into()];
        let mut p = probe(&r, 0, 5000);
        let e = witness(&r.cfg, &mut p).unwrap_err();
        assert!(e.contains("exited at startup") && e.contains("boom"), "{e}");
        done(r);
    }
}

/// LR N1: the acceptance of `linux_wire.rs` (`rmasscan-net/tests/common/wire_meta.rs`, one
/// predicate shared by both crates) must accept what `witness()` really writes, over the
/// committed golden frames, and must still reject any loss.
#[cfg(unix)]
mod linux_wire_gate {
    use super::sequence::*;
    use super::*;

    mod wire_meta {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rmasscan-net/tests/common/wire_meta.rs"
        ));
    }

    pub(super) fn golden(case: &str) -> Vec<Vec<u8>> {
        let p = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join(format!("../../tests/golden/wire/{case}.run1.pcap"));
        let bytes = fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        crate::pcap::read_pcap_records(&bytes)
            .unwrap()
            .1
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }
    fn compact(meta: &serde_json::Value) -> String {
        serde_json::to_string(meta).unwrap()
    }
    const CASES: [&str; 6] = [
        "c01_one_addr_port_synack",
        "c02_one_addr_port_rst",
        "c03_multi_addr_ports",
        "c04_exclude",
        "c05_srcport_single",
        "c06_srcport_range",
    ];

    #[test]
    fn real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate() {
        for case in CASES {
            let mut all = vec![crate::link::marker_frame([2; 6], [1; 6], START_PAYLOAD)];
            all.extend(golden(case));
            for _ in 0..3 {
                all.push(crate::link::marker_frame([1; 6], [2; 6], END_PAYLOAD));
            }
            let n = all.len() as u64;
            let r = rig(&format!("gate-{case}"), LISTENING, all, &stats(n, 0));
            let mut p = probe(&r, n, 5000);
            let meta = witness(&r.cfg, &mut p).unwrap();
            assert_eq!(meta["valid"], true, "{case}: {meta}");
            assert_eq!(
                wire_meta::capture_meta_problem(&compact(&meta)),
                None,
                "{case}: a valid witness meta was rejected: {meta}"
            );
            done(r);
        }
    }

    #[test]
    fn any_loss_in_a_real_witness_meta_fails_the_linux_wire_gate() {
        let mk = |tag: &str, st: String, drops: Vec<u64>| {
            let mut all = vec![crate::link::marker_frame([2; 6], [1; 6], START_PAYLOAD)];
            all.extend(golden("c03_multi_addr_ports"));
            for _ in 0..3 {
                all.push(crate::link::marker_frame([1; 6], [2; 6], END_PAYLOAD));
            }
            let n = all.len() as u64;
            let r = rig(tag, LISTENING, all, &st);
            let mut p = probe(&r, n, 5000);
            p.drops = drops;
            let meta = witness(&r.cfg, &mut p).unwrap();
            done(r);
            meta
        };
        let n = 1 + golden("c03_multi_addr_ports").len() as u64 + 3;
        // A kernel drop.
        let m = mk("gate-kdrop", stats(n, 1), vec![0]);
        assert!(
            wire_meta::capture_meta_problem(&compact(&m)).is_some(),
            "{m}"
        );
        // An interface drop (sysfs delta).
        let m = mk("gate-idrop", stats(n, 0), vec![0, 1]);
        assert!(
            wire_meta::capture_meta_problem(&compact(&m)).is_some(),
            "{m}"
        );
        // An interface drop reported by tcpdump itself.
        let st = format!(
            "{n} packets captured\n{n} packets received by filter\n0 packets dropped by kernel\n2 packets dropped by interface\n"
        );
        let m = mk("gate-ifline", st, vec![0]);
        assert!(
            wire_meta::capture_meta_problem(&compact(&m)).is_some(),
            "{m}"
        );
    }

    #[test]
    fn the_shared_sample_meta_has_exactly_the_keys_the_real_witness_writes() {
        let mut all = vec![crate::link::marker_frame([2; 6], [1; 6], START_PAYLOAD)];
        all.extend(golden("c01_one_addr_port_synack"));
        for _ in 0..3 {
            all.push(crate::link::marker_frame([1; 6], [2; 6], END_PAYLOAD));
        }
        let n = all.len() as u64;
        let r = rig("gate-keys", LISTENING, all, &stats(n, 0));
        let mut p = probe(&r, n, 5000);
        let real = witness(&r.cfg, &mut p).unwrap();
        done(r);
        let sample: serde_json::Value = serde_json::from_str(wire_meta::SAMPLE_META).unwrap();
        let keys =
            |v: &serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(keys(&real), keys(&sample));
        assert_eq!(
            wire_meta::capture_meta_problem(wire_meta::SAMPLE_META),
            None
        );
    }

    #[test]
    fn the_gate_rejects_hand_edited_metas() {
        let ok = r#"{"interface_drop_delta":0,"interface_drops":0,"invalid_reasons":[],"kernel_drops":0,"valid":true}"#;
        assert_eq!(wire_meta::capture_meta_problem(ok), None);
        // tcpdump without the "dropped by interface" line: the measured delta decides.
        let null_if = ok.replace("\"interface_drops\":0", "\"interface_drops\":null");
        assert_eq!(wire_meta::capture_meta_problem(&null_if), None);
        for bad in [
            ok.replace("\"kernel_drops\":0", "\"kernel_drops\":1"),
            ok.replace("\"kernel_drops\":0", "\"kernel_drops\":null"),
            ok.replace("\"interface_drop_delta\":0", "\"interface_drop_delta\":3"),
            ok.replace(
                "\"interface_drop_delta\":0",
                "\"interface_drop_delta\":null",
            ),
            ok.replace("\"interface_drops\":0", "\"interface_drops\":2"),
            ok.replace("\"valid\":true", "\"valid\":false"),
            ok.replace("\"invalid_reasons\":[]", "\"invalid_reasons\":[\"x\"]"),
            ok.replace("\"kernel_drops\":0,", ""),
            ok.replace("\"kernel_drops\":0", "\"kernel_drops\":10"),
        ] {
            assert!(wire_meta::capture_meta_problem(&bad).is_some(), "{bad}");
        }
    }
}

mod macos_probe {
    use super::super::*;

    // Recorded from macOS (`netstat -I IFACE -b -d -n`), values shortened.
    const WITH_DROP: &str = "\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll Drop
en0        1500  <Link#14>   82:fe:61:f5:ac:74 51497279     3 63224918459 20542225     0 16067097062     0   7
en0        1500  fe80::1816: fe80:e::1816:7266 51497279     - 63224918459 20542225     - 16067097062     -   -
";
    const NO_ADDRESS: &str = "\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll Drop
lo0        16384 <Link#1>                       1627524     1 2955813050  1627525     0 2955813050     0   2
lo0        16384 127           127.0.0.1        1627524     - 2955813050  1627524     - 2955813050     -   -
";
    const NO_DROP_COLUMN: &str = "\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0        1500  <Link#14>   82:fe:61:f5:ac:74 51497279     0 63224918459 20542225     0 16067097062     0
";

    #[test]
    fn netstat_row_with_drop_column_is_parsed_by_header_name() {
        let c = parse_netstat(WITH_DROP, "en0").unwrap();
        assert_eq!(
            c,
            NetstatCounters {
                ipkts: 51497279,
                opkts: 20542225,
                ierrs: 3,
                drop: 7
            }
        );
    }

    #[test]
    fn netstat_link_row_without_an_address_shifts_the_columns() {
        let c = parse_netstat(NO_ADDRESS, "lo0").unwrap();
        assert_eq!(
            (c.ipkts, c.opkts, c.ierrs, c.drop),
            (1627524, 1627525, 1, 2)
        );
    }

    #[test]
    fn netstat_without_a_drop_column_is_an_error_not_zero() {
        let e = parse_netstat(NO_DROP_COLUMN, "en0").unwrap_err();
        assert!(e.contains("Drop"), "{e}");
    }

    #[test]
    fn netstat_unknown_interface_and_empty_text_are_errors() {
        assert!(parse_netstat(WITH_DROP, "en9").is_err());
        assert!(parse_netstat("", "en0").is_err());
    }

    #[test]
    fn macos_tcpdump_argv_has_no_linux_only_flags_and_one_filter_argument() {
        let plain = tcpdump_argv_macos("feth4202", "/x/p.pcap", None);
        assert_eq!(
            plain,
            [
                "tcpdump",
                "-i",
                "feth4202",
                "-n",
                "-U",
                "--immediate-mode",
                "-s",
                "0",
                "-w",
                "/x/p.pcap"
            ]
        );
        for banned in ["-Z", "-B", "--time-stamp-precision=nano"] {
            assert!(!plain.iter().any(|a| a == banned), "{banned}");
        }
        let f = "net 198.18.0.0/30 or ether proto 0x88b5";
        let with = tcpdump_argv_macos("en0", "/x/u.pcap", Some(f));
        assert_eq!(with.last().map(String::as_str), Some(f));
        assert_eq!(with.len(), plain.len() + 1);
    }
}
