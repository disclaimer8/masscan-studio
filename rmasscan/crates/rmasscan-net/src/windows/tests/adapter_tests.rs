//! Тесты половин адаптера через подставную таблицу функций wpcap (`fake`):
//! настоящий `PcapHandle`, настоящие `TxHalf`/`RxHalf`, настоящий движок.

use std::ffi::c_int;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ProbeCursor, ReadyPlan};
use rmasscan_core::receive::{PortStatus, parse_reply};
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::fake::reply_to_syn;
use rmasscan_engine::{
    AdapterPair, Engine, EngineOptions, Event, FailReason, IoError, Reason, SendStatus, Tx, TxBatch,
};

use super::fake::*;
use super::good_api;
use crate::NetError;
use crate::TxMode;
use crate::windows::adapter::{
    IO_BUDGET, MAX_TX_FRAME, MIN_TX_FRAME, TX_BATCH_FRAMES, TX_QUEUE_BYTES, batch_outcome,
    check_binding, mac_text, open_with,
};
use crate::windows::ffi::SENDQUEUE_RECORD_HEADER;
use crate::windows::loader::{ApiSlot, NpcapApi};

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x04, 0x80, 0xa9];
const PEER_MAC: [u8; 6] = [0x02, 0x57, 0x4c, 0x3d, 0x2e, 0x9b];
const PROBES: u64 = 16;

fn binding() -> AdapterBinding {
    AdapterBinding {
        interface_id: DEV1.into(),
        link_type: LinkType::Ethernet,
        source_ipv4: 0x0aff_0001,
        source_mac: OUR_MAC,
        next_hop_mac: PEER_MAC,
        source_ports: (40000, 40015),
    }
}

fn plan(rate: f64, wait: u32) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), "10.0.0.0/29").unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: 0x1234_5678_9abc,
        max_rate: rate,
        wait_secs: wait,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(eff, binding()).unwrap()
}

/// Настоящий SYN-кадр плана (с индексом `i`).
fn syn_frame(plan: &ReadyPlan, i: usize) -> Vec<u8> {
    let mut c = ProbeCursor::new(plan, 0).unwrap();
    for _ in 0..i {
        c.advance_sent();
    }
    c.current().unwrap().frame.clone()
}

fn open_pair(api: &Arc<NpcapApi>) -> crate::OpenedAdapter {
    open_with(api, &binding()).expect("open_with")
}

fn buf() -> Vec<u8> {
    vec![0u8; 2048]
}

fn own_frame(len: usize) -> Vec<u8> {
    let mut f = vec![0u8; len];
    f[0..6].copy_from_slice(&PEER_MAC);
    f[6..12].copy_from_slice(&OUR_MAC);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f
}

fn peer_frame(len: usize) -> Vec<u8> {
    let mut f = own_frame(len);
    f[0..6].copy_from_slice(&OUR_MAC);
    f[6..12].copy_from_slice(&PEER_MAC);
    f
}

// ---------- pcap_init, память загрузки ----------

#[test]
fn pcap_init_utf8_runs_before_any_other_call_into_the_library() {
    reset(|_| {});
    let api = good_api();
    let ev = events();
    let init = pos(&ev, "init:1");
    assert!(init < pos(&ev, "lib_version"), "{ev:?}");
    assert_eq!(ev.iter().position(|e| e.starts_with("init")), Some(init));
    assert!(api.utf8_text());
}

#[test]
fn missing_or_failing_pcap_init_is_not_fatal_and_is_reported() {
    reset(|_| {});
    let l = super::FakeLoader {
        no_init: true,
        ..super::FakeLoader::ok()
    };
    let api = NpcapApi::load_with(&l, GOOD_PATH).unwrap();
    assert!(!api.utf8_text());
    assert!(!events().iter().any(|e| e.starts_with("init")));
    drop(api);

    reset(|s| s.init_rc = -1);
    let api = good_api();
    assert!(!api.utf8_text());
    assert!(events().contains(&"init:1".to_string()));
}

#[test]
fn load_is_shared_while_an_owner_lives_reloaded_after_and_failure_is_not_cached() {
    reset(|_| {});
    let slot = ApiSlot::new();
    let loads = AtomicUsize::new(0);
    let load = || {
        loads.fetch_add(1, Ordering::SeqCst);
        NpcapApi::load_with(&super::FakeLoader::ok(), GOOD_PATH)
    };
    let a = slot.get_or_load(load).unwrap();
    let b = slot.get_or_load(load).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    drop((a, b));
    assert_eq!(count("unload"), 1);
    let c = slot.get_or_load(load).unwrap();
    assert_eq!(
        loads.load(Ordering::SeqCst),
        2,
        "reloaded after the last owner"
    );
    drop(c);

    // Ошибка не кэшируется: следующий вызов пробует снова.
    let fail =
        || -> Result<Arc<NpcapApi>, NetError> { Err(NetError::DriverUnavailable("x".into())) };
    assert!(slot.get_or_load(fail).is_err());
    assert!(slot.get_or_load(load).is_ok());
    assert_eq!(loads.load(Ordering::SeqCst), 3);
}

#[test]
fn concurrent_first_loads_run_the_loader_once() {
    reset(|_| {});
    let slot = Arc::new(ApiSlot::new());
    let loads = Arc::new(AtomicUsize::new(0));
    let keep = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..8 {
            let (slot, loads, keep) = (&slot, &loads, &keep);
            sc.spawn(move || {
                let a = slot
                    .get_or_load(|| {
                        loads.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        NpcapApi::load_with(&super::FakeLoader::ok(), GOOD_PATH)
                    })
                    .unwrap();
                keep.lock().unwrap().push(a);
            });
        }
    });
    assert_eq!(loads.load(Ordering::SeqCst), 1);
}

// ---------- binding и открытие ----------

#[test]
fn bad_bindings_are_refused_before_the_driver_is_touched() {
    reset(|_| {});
    let api = good_api();
    let before = events().len();
    let mut cases = Vec::new();
    let mut b = binding();
    b.link_type = LinkType::Raw;
    cases.push(("raw link", b, "unsupported"));
    let mut b = binding();
    b.source_mac = [0; 6];
    cases.push(("zero mac", b, "mismatch"));
    let mut b = binding();
    b.source_mac = [0x01, 0, 0x5e, 0, 0, 1];
    cases.push(("multicast mac", b, "mismatch"));
    let mut b = binding();
    b.next_hop_mac = b.source_mac;
    cases.push(("source == next hop", b, "mismatch"));
    for (label, b, want) in cases {
        let e = open_with(&api, &b)
            .err()
            .unwrap_or_else(|| panic!("{label}"));
        match (&e, want) {
            (NetError::UnsupportedLink(_), "unsupported") => {}
            (NetError::InterfaceMismatch(_), "mismatch") => {}
            _ => panic!("{label}: {e:?}"),
        }
        assert!(check_binding(&b).is_err(), "{label}");
    }
    assert_eq!(events().len(), before, "no create/enumeration happened");
}

#[test]
fn open_configures_two_handles_exactly_as_documented() {
    reset(|_| {});
    let api = good_api();
    let a = open_pair(&api);
    let ev = events();
    assert_eq!(ev.iter().filter(|e| *e == "create").count(), 2);
    assert!(
        !ev.contains(&"set_promisc:1".to_string()),
        "promiscuous mode must stay off"
    );
    with(|s| {
        // handle 1 = TX: фильтр «ничего» (ret #0), без pcap_compile.
        let tx_f: Vec<_> = s.filters.iter().filter(|(h, _)| *h == 1).collect();
        assert_eq!(tx_f.len(), 1);
        assert_eq!(tx_f[0].1.len(), 1);
        assert_eq!((tx_f[0].1[0].code, tx_f[0].1[0].k), (0x06, 0));
        // handle 2 = RX: только отсев НАШЕГО source MAC.
        assert_eq!(
            s.compiled,
            vec![(2, "not ether src 52:54:00:04:80:a9".to_string())]
        );
        assert_eq!(s.filters.iter().filter(|(h, _)| *h == 2).count(), 1);
        assert_eq!(s.freecode_calls, 1, "compiled program is freed");
        assert_eq!(s.stats_calls, 1, "baseline read once");
        // nonblocking только на RX.
        assert!(!s.compiled.iter().any(|(h, _)| *h == 1));
    });
    assert_eq!(count("setnonblock:1"), 1);
    drop(a);
    assert_eq!(count("close"), 2);
    drop(api);
    let ev = events();
    assert!(ev.iter().rposition(|e| e == "close") < ev.iter().rposition(|e| e == "unload"));
}

#[test]
fn every_open_failure_after_the_first_handle_closes_all_handles_before_unload() {
    type Tweak = fn(&mut Scenario);
    let cases: Vec<(&str, Tweak, usize)> = vec![
        (
            "second create returns NULL",
            |s| s.create_null_nth = Some(2),
            1,
        ),
        (
            "second activate denied",
            |s| s.activate_fail_nth = Some((2, -8)),
            2,
        ),
        (
            "tx drop-all filter rejected",
            |s| s.setfilter_fail_hid = Some((1, -1)),
            1,
        ),
        ("rx compile fails", |s| s.compile_rc = -1, 2),
        (
            "rx setfilter rejected",
            |s| s.setfilter_fail_hid = Some((2, -1)),
            2,
        ),
        (
            "baseline stats fails",
            |s| s.stats_script.push_back(Err(-3)),
            2,
        ),
        ("setnonblock fails", |s| s.setnonblock_rc = -1, 2),
        (
            "sendqueue alloc fails",
            |s| s.sendqueue_alloc_null = true,
            1,
        ),
        (
            "nonblock does not stick",
            |s| s.getnonblock_override = Some(0),
            2,
        ),
    ];
    for (label, tweak, closes) in cases {
        reset(tweak);
        let api = good_api();
        let e = open_with(&api, &binding())
            .err()
            .unwrap_or_else(|| panic!("{label}"));
        assert!(
            !matches!(e, NetError::UnsupportedPlatform),
            "{label}: {e:?}"
        );
        let ev = events();
        assert_eq!(count("close"), closes, "{label}: {ev:?}");
        assert!(!ev.contains(&"unload".to_string()), "{label}: {ev:?}");
        let (compiled_ok, freed) = with_ret(|s| {
            (
                if s.compile_rc == 0 {
                    s.compiled.len()
                } else {
                    0
                },
                s.freecode_calls,
            )
        });
        assert_eq!(freed, compiled_ok, "{label}: compiled program leaked");
        assert_eq!(
            with_ret(|s| s.queues.len()),
            0,
            "{label}: send queue leaked"
        );
        let ev = events();
        if let (Some(a), Some(d)) = (
            ev.iter().position(|e| e.starts_with("sendqueue_alloc")),
            ev.iter().position(|e| e == "sendqueue_destroy"),
        ) {
            let first_close = pos(&ev, "close:1");
            assert!(
                a < d && d < first_close,
                "{label}: queue outlived the TX handle"
            );
        }
        drop(api);
        let ev = events();
        assert!(
            ev.iter().rposition(|e| e == "close") < ev.iter().rposition(|e| e == "unload"),
            "{label}: {ev:?}"
        );
    }
}

fn with_ret<T>(f: impl FnOnce(&mut Scenario) -> T) -> T {
    let mut out = None;
    with(|s| out = Some(f(s)));
    out.unwrap()
}

#[test]
fn non_ethernet_device_is_refused_and_closed() {
    reset(|s| s.dlt = 0);
    let api = good_api();
    let e = open_with(&api, &binding()).err().unwrap();
    assert!(matches!(e, NetError::UnsupportedLink(_)), "{e:?}");
    assert_eq!(count("close"), 1);
}

#[test]
fn unknown_device_name_never_creates_a_handle() {
    reset(|_| {});
    let api = good_api();
    let mut b = binding();
    b.interface_id = "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}".into();
    assert!(matches!(
        open_with(&api, &b).err().unwrap(),
        NetError::InterfaceMismatch(_)
    ));
    assert_eq!(count("create"), 0);
}

// ---------- RX ----------

#[test]
fn idle_rx_waits_to_the_internal_budget_and_never_longer() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let t = Instant::now();
    let r = a.io.rx.recv(&mut b, Duration::from_millis(50)).unwrap();
    let e = t.elapsed();
    assert_eq!(r, None);
    assert!(e >= IO_BUDGET, "returned early: {e:?}");
    assert!(e < Duration::from_millis(100), "overran: {e:?}");
    assert!(with_ret(|s| s.next_calls) > 3, "must keep polling");
}

#[test]
fn a_short_timeout_is_honoured_and_a_long_one_is_clamped() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let t = Instant::now();
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(5)).unwrap(),
        None
    );
    let e = t.elapsed();
    assert!(
        e >= Duration::from_millis(5) && e < Duration::from_millis(40),
        "{e:?}"
    );
    let t = Instant::now();
    assert_eq!(a.io.rx.recv(&mut b, Duration::from_secs(5)).unwrap(), None);
    assert!(
        t.elapsed() < Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(a.io.rx.recv(&mut b, Duration::ZERO).unwrap(), None);
}

#[test]
fn a_frame_is_copied_before_the_next_pcap_call() {
    reset(|s| {
        s.next_script.push_back(NextStep::Frame(peer_frame(60)));
        s.next_script.push_back(NextStep::Frame(vec![0x77; 80]));
    });
    let api = good_api();
    let mut a = open_pair(&api);
    let (mut b1, mut b2) = (buf(), buf());
    let n1 =
        a.io.rx
            .recv(&mut b1, Duration::from_millis(50))
            .unwrap()
            .unwrap();
    let n2 =
        a.io.rx
            .recv(&mut b2, Duration::from_millis(50))
            .unwrap()
            .unwrap();
    // Между вызовами подставная библиотека затёрла свой буфер (0xAA).
    assert_eq!((n1, n2), (60, 80));
    assert_eq!(b1[..60], peer_frame(60)[..]);
    assert_eq!(b2[..80], [0x77; 80]);
}

#[test]
fn a_returned_frame_is_the_exact_pcap_frame_and_counted() {
    reset(|s| s.next_script.push_back(NextStep::Frame(peer_frame(77))));
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let n =
        a.io.rx
            .recv(&mut b, Duration::from_millis(50))
            .unwrap()
            .unwrap();
    assert_eq!(&b[..n], &peer_frame(77)[..]);
    assert_eq!(a.stats.snapshot().rx_packets, 1);
}

#[test]
fn runt_frames_pass_through_without_panicking() {
    reset(|s| {
        s.next_script.push_back(NextStep::Frame(vec![]));
        s.next_script.push_back(NextStep::Frame(vec![1, 2, 3]));
    });
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(50)).unwrap(),
        Some(0)
    );
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(50)).unwrap(),
        Some(3)
    );
}

#[test]
fn own_transmitted_frames_are_dropped_before_the_caller_sees_them() {
    reset(|s| {
        s.next_script.push_back(NextStep::Frame(own_frame(60)));
        s.next_script.push_back(NextStep::Frame(own_frame(90)));
        s.next_script.push_back(NextStep::Frame(peer_frame(64)));
    });
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let n =
        a.io.rx
            .recv(&mut b, Duration::from_millis(50))
            .unwrap()
            .unwrap();
    assert_eq!(n, 64, "the peer frame is returned, our own two are not");
    let s = a.stats.snapshot();
    assert_eq!((s.rx_outgoing, s.rx_packets), (2, 1));
}

#[test]
fn peer_syn_ack_and_rst_are_never_filtered_and_parse_as_replies() {
    let p = plan(1e6, 1);
    let syn = syn_frame(&p, 0);
    let synack = reply_to_syn(&syn, 0x12).unwrap();
    let rst = reply_to_syn(&syn_frame(&p, 1), 0x04).unwrap();
    assert_eq!(synack[6..12], PEER_MAC, "reply source is the peer");
    reset(|s| {
        s.next_script.push_back(NextStep::Frame(syn.clone())); // наш SYN (эхо)
        s.next_script.push_back(NextStep::Frame(synack.clone()));
        s.next_script.push_back(NextStep::Frame(rst.clone()));
    });
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let mut got = Vec::new();
    while let Some(n) = a.io.rx.recv(&mut b, Duration::from_millis(10)).unwrap() {
        got.push(b[..n].to_vec());
    }
    assert_eq!(got, vec![synack.clone(), rst.clone()]);
    let r1 = parse_reply(&got[0], LinkType::Ethernet, &p)
        .unwrap()
        .unwrap();
    let r2 = parse_reply(&got[1], LinkType::Ethernet, &p)
        .unwrap()
        .unwrap();
    assert_eq!(r1.status, PortStatus::Open);
    assert_eq!(r2.status, PortStatus::Closed);
    // Единственный фильтр режет только кадры с НАШИМ source MAC.
    with(|s| {
        assert_eq!(s.compiled.len(), 1);
        let e = &s.compiled[0].1;
        assert_eq!(e, &format!("not ether src {}", mac_text(&OUR_MAC)));
        assert!(!e.contains(&mac_text(&PEER_MAC)));
    });
}

#[test]
fn a_stream_of_garbage_does_not_extend_the_deadline() {
    reset(|s| s.junk_forever = Some(own_frame(60)));
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let t = Instant::now();
    let r = a.io.rx.recv(&mut b, Duration::from_millis(50)).unwrap();
    let e = t.elapsed();
    assert_eq!(r, None);
    assert!(e >= IO_BUDGET && e < Duration::from_millis(100), "{e:?}");
    assert!(a.stats.snapshot().rx_outgoing > 100, "garbage was consumed");
}

#[test]
fn truncated_frames_are_counted_and_dropped_not_returned() {
    reset(|s| {
        // snaplen обрезал кадр: caplen < len.
        s.next_script.push_back(NextStep::Raw {
            caplen: 60,
            len: 100,
            data: vec![0x11; 60],
        });
        // caplen > len: нарушение согласованности, тоже усечение.
        s.next_script.push_back(NextStep::Raw {
            caplen: 70,
            len: 60,
            data: vec![0x22; 70],
        });
    });
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    assert_eq!(
        a.io.rx.recv(&mut b, Duration::from_millis(5)).unwrap(),
        None
    );
    assert_eq!(a.stats.snapshot().rx_truncated, 2);
    assert!(b.iter().all(|x| *x == 0), "truncated data was not copied");
}

#[test]
fn a_frame_larger_than_the_callers_buffer_is_dropped_and_counted() {
    reset(|s| s.next_script.push_back(NextStep::Frame(peer_frame(200))));
    let api = good_api();
    let mut a = open_pair(&api);
    let mut small = vec![0u8; 64];
    assert_eq!(
        a.io.rx.recv(&mut small, Duration::from_millis(5)).unwrap(),
        None
    );
    assert_eq!(a.stats.snapshot().rx_truncated, 1);
    assert!(small.iter().all(|x| *x == 0));
}

#[test]
fn malformed_library_output_is_a_fatal_error_that_closes_the_handle() {
    let cases: Vec<(&str, NextStep)> = vec![
        ("null header", NextStep::NullHdr),
        ("null data", NextStep::NullData),
        (
            "caplen above snaplen",
            NextStep::Raw {
                caplen: 0xFFFF_FFF0,
                len: 0xFFFF_FFF0,
                data: vec![0; 8],
            },
        ),
        (
            "caplen just above snaplen",
            NextStep::Raw {
                caplen: 2049,
                len: 2049,
                data: vec![0; 2049],
            },
        ),
    ];
    for (label, step) in cases {
        reset(|s| s.next_script.push_back(step.clone()));
        let api = good_api();
        let mut a = open_pair(&api);
        let mut b = buf();
        let e = a.io.rx.recv(&mut b, Duration::from_millis(50)).err();
        assert!(e.is_some(), "{label}");
        assert_eq!(a.stats.snapshot().rx_errors, 1, "{label}");
        assert_eq!(count("close"), 1, "{label}: RX handle closed at once");
        assert!(a.io.rx.recv(&mut b, Duration::from_millis(5)).is_err());
        assert!(
            a.io.rx.health(Duration::from_millis(50)).is_err(),
            "{label}"
        );
    }
}

#[test]
fn next_ex_error_and_eof_are_fatal_and_carry_the_driver_text() {
    reset(|s| s.next_script.push_back(NextStep::Err(-1)));
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    let e: IoError = a.io.rx.recv(&mut b, Duration::from_millis(50)).unwrap_err();
    assert!(
        e.message.contains("code -1") && e.message.contains("fake driver says no"),
        "{e:?}"
    );
    assert_eq!(a.stats.snapshot().rx_errors, 1);
    assert!(a.io.rx.recv(&mut b, Duration::from_millis(5)).is_err());

    reset(|s| s.next_script.push_back(NextStep::Eof));
    let api = good_api();
    let mut a = open_pair(&api);
    let e = a.io.rx.recv(&mut b, Duration::from_millis(50)).unwrap_err();
    assert!(e.message.contains("EOF"), "{e:?}");
}

// ---------- TX ----------

#[test]
fn send_rc_zero_is_sent_exactly_once() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let f = own_frame(60);
    assert_eq!(
        a.io.tx.send(&f, Duration::from_millis(50)).unwrap(),
        SendStatus::Sent
    );
    let s = a.stats.snapshot();
    assert_eq!(
        (s.tx_sent, s.tx_uncertain, s.tx_would_block, s.tx_errors),
        (1, 0, 0, 0)
    );
    with(|s| {
        assert_eq!(s.send_calls, 1);
        assert_eq!(s.sent, vec![f.clone()]);
    });
}

#[test]
fn any_nonzero_send_rc_is_uncertain_without_a_retry_and_ignores_the_driver_text() {
    for rc in [-1, 1, -3, c_int::MIN, c_int::MAX] {
        // Текст ошибки похож на «буфер полон»: он не должен ничего менять.
        reset(|s| {
            s.send_rcs.push_back(rc);
            s.geterr =
                std::ffi::CString::new("send buffer is full, would block, try again").unwrap();
        });
        let api = good_api();
        let mut a = open_pair(&api);
        let st =
            a.io.tx
                .send(&own_frame(60), Duration::from_millis(50))
                .unwrap();
        assert_eq!(st, SendStatus::Uncertain, "rc {rc}");
        let s = a.stats.snapshot();
        assert_eq!(
            (s.tx_sent, s.tx_uncertain, s.tx_would_block),
            (0, 1, 0),
            "rc {rc}"
        );
        assert_eq!(with_ret(|s| s.send_calls), 1, "rc {rc}: no retry");
    }
}

#[test]
fn pre_send_validation_errors_are_io_errors_and_never_reach_the_driver() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    for len in [0, 1, MIN_TX_FRAME - 1, MAX_TX_FRAME + 1, 9000, 70_000] {
        let e =
            a.io.tx
                .send(&vec![0u8; len], Duration::from_millis(50))
                .unwrap_err();
        assert!(e.message.contains("nothing was sent"), "{len}: {e:?}");
    }
    assert_eq!(with_ret(|s| s.send_calls), 0);
    let s = a.stats.snapshot();
    assert_eq!((s.tx_errors, s.tx_sent), (6, 0));
    // Граничные длины допустимы, и handle остался рабочим.
    for len in [MIN_TX_FRAME, MAX_TX_FRAME] {
        assert_eq!(
            a.io.tx
                .send(&vec![0u8; len], Duration::from_millis(50))
                .unwrap(),
            SendStatus::Sent
        );
    }
}

// ---------- health и счётчики ----------

#[test]
fn health_reports_the_cumulative_per_attempt_drop_count() {
    reset(|s| s.stats_drop = 1000); // baseline: handle уже видел 1000
    let api = good_api();
    let mut a = open_pair(&api);
    let h = |a: &mut crate::OpenedAdapter| a.io.rx.health(Duration::from_millis(50));
    assert_eq!(h(&mut a).unwrap().kernel_drops, Some(0));
    with(|s| s.stats_drop = 1007);
    assert_eq!(h(&mut a).unwrap().kernel_drops, Some(7));
    assert_eq!(
        h(&mut a).unwrap().kernel_drops,
        Some(7),
        "reading does not reset"
    );
    with(|s| s.stats_drop = 1010);
    assert_eq!(h(&mut a).unwrap().kernel_drops, Some(10));
}

#[test]
fn health_survives_the_u32_wrap() {
    reset(|s| s.stats_drop = u32::MAX - 2);
    let api = good_api();
    let mut a = open_pair(&api);
    with(|s| s.stats_drop = u32::MAX);
    assert_eq!(
        a.io.rx
            .health(Duration::from_millis(50))
            .unwrap()
            .kernel_drops,
        Some(2)
    );
    with(|s| s.stats_drop = 1);
    assert_eq!(
        a.io.rx
            .health(Duration::from_millis(50))
            .unwrap()
            .kernel_drops,
        Some(4)
    );
}

#[test]
fn a_stats_error_is_an_error_never_a_false_zero_or_a_cached_value() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    // Ни одного успешного измерения ещё не было: и сразу ошибка.
    with(|s| s.stats_script.push_back(Err(-3)));
    let e = a.io.rx.health(Duration::from_millis(50)).unwrap_err();
    assert!(
        e.message.contains("code -3") && e.message.contains("fake driver says no"),
        "{e:?}"
    );
    assert_eq!(
        a.stats.snapshot().kernel_drops,
        None,
        "unknown stays unknown"
    );
    // После успеха и новой ошибки прежнее значение не подставляется.
    with(|s| s.stats_drop = 5);
    assert_eq!(
        a.io.rx
            .health(Duration::from_millis(50))
            .unwrap()
            .kernel_drops,
        Some(5)
    );
    with(|s| s.stats_script.push_back(Err(-1)));
    assert!(a.io.rx.health(Duration::from_millis(50)).is_err());
    assert_eq!(
        a.io.rx
            .health(Duration::from_millis(50))
            .unwrap()
            .kernel_drops,
        Some(5)
    );
}

#[test]
fn net_stats_final_totals_survive_closing_the_handles() {
    reset(|_| {});
    let api = good_api();
    let a = open_pair(&api);
    let stats = a.stats.clone();
    assert_eq!(stats.snapshot().kernel_drops, None, "nothing measured yet");
    with(|s| s.stats_drop = 9);
    let crate::OpenedAdapter { io, .. } = a;
    drop(io);
    assert_eq!(count("close"), 2);
    assert_eq!(
        stats.snapshot().kernel_drops,
        Some(9),
        "final read on close"
    );
}

#[test]
fn a_failed_final_read_keeps_the_last_known_value_or_none() {
    reset(|_| {});
    let api = good_api();
    let a = open_pair(&api);
    let stats = a.stats.clone();
    with(|s| s.stats_script.push_back(Err(-1)));
    drop(a);
    assert_eq!(stats.snapshot().kernel_drops, None);

    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let stats = a.stats.clone();
    with(|s| s.stats_drop = 4);
    a.io.rx.health(Duration::from_millis(50)).unwrap();
    with(|s| s.stats_script.push_back(Err(-1)));
    drop(a);
    assert_eq!(stats.snapshot().kernel_drops, Some(4));
}

// ---------- общий runtime ----------

fn engine_pair(a: crate::OpenedAdapter) -> (AdapterPair, crate::NetStatsHandle) {
    (a.io, a.stats)
}

fn start(p: &ReadyPlan, io: AdapterPair, attempt: u8) -> rmasscan_engine::EngineHandle {
    Engine::start(p.clone(), io, EngineOptions::new([1; 16], [attempt; 16])).unwrap()
}

fn finish(h: rmasscan_engine::EngineHandle) -> (rmasscan_engine::Outcome, Vec<Event>) {
    h.join_drain().unwrap()
}

fn replies(events: &[Event]) -> Vec<rmasscan_core::receive::Reply> {
    events
        .iter()
        .flat_map(|e| match e {
            Event::Results { replies } => replies.clone(),
            _ => vec![],
        })
        .collect()
}

fn syn_ack_responder() {
    with(|s| {
        s.responder = Some(Arc::new(|f: &[u8]| {
            reply_to_syn(f, 0x12).into_iter().collect()
        }));
        s.echo_tx = true;
    });
}

#[test]
fn a_full_scan_through_the_engine_completes_with_exactly_one_advance_per_sent() {
    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let p = plan(1e6, 1);
    let (io, stats) = engine_pair(open_pair(&api));
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(out.reason, Reason::Completed, "{out:?}");
    assert_eq!(out.progress.sent, PROBES);
    assert_eq!(out.progress.next_index, PROBES);
    assert_eq!(out.rx_health.kernel_drops, Some(0));
    assert_eq!(replies(&events).len() as u64, PROBES);
    let s = stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_uncertain, s.tx_errors), (PROBES, 0, 0));
    assert_eq!(
        s.rx_outgoing, PROBES,
        "our own echoed SYNs were dropped before parsing"
    );
    assert_eq!(s.rx_packets, PROBES);
    assert_eq!(s.kernel_drops, Some(0));
    with(|st| {
        assert_eq!(st.send_calls as u64, PROBES);
        // Каждый кадр плана ушёл ровно один раз и по порядку.
        for (i, f) in st.sent.iter().enumerate() {
            assert_eq!(*f, syn_frame(&p, i));
        }
    });
}

#[test]
fn an_uncertain_send_fails_the_run_without_checkpoint_retry_or_more_sends() {
    reset(|s| s.send_rcs.extend([0, 0, -1]));
    syn_ack_responder();
    let api = good_api();
    let p = plan(1e6, 1);
    let (io, _stats) = engine_pair(open_pair(&api));
    let h = start(&p, io, 2);
    let (out, events) = finish(h);
    assert_eq!(out.reason, Reason::Failed(FailReason::TxUncertain));
    assert_eq!(out.progress.sent, 2);
    assert_eq!(out.progress.next_index, 2);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        with_ret(|s| s.send_calls),
        3,
        "no retry, nothing after the outcome"
    );
    assert_eq!(
        count("close"),
        2,
        "both handles are closed once the run ends"
    );
}

#[test]
fn stop_ends_the_run_quickly_and_nothing_is_sent_afterwards() {
    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let p = plan(10.0, 3); // медленный TX, длинное ожидание ответов
    let (io, stats) = engine_pair(open_pair(&api));
    let h = start(&p, io, 2);
    while h.progress().sent < 2 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let t = Instant::now();
    h.stop();
    let (out, _) = finish(h);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(out.reason, Reason::Stopped, "{out:?}");
    let sent_at_join = with_ret(|s| s.send_calls);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        with_ret(|s| s.send_calls),
        sent_at_join,
        "a worker sent after Stop"
    );
    assert_eq!(stats.snapshot().tx_sent as usize, sent_at_join);
    assert_eq!(count("close"), 2);
}

#[test]
fn pause_stops_tx_then_resume_continues_without_gaps_or_duplicates() {
    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let p = plan(40.0, 1);
    let (io, _stats) = engine_pair(open_pair(&api));
    let h = start(&p, io, 2);
    while h.progress().sent < 3 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let t = Instant::now();
    h.pause();
    while h.outcome().is_none() {
        assert!(t.elapsed() < Duration::from_secs(4), "pause did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    let cp = h.checkpoint().expect("a paused run carries a checkpoint");
    let (out, _) = finish(h);
    assert!(
        t.elapsed() < Duration::from_secs(4),
        "pause + wait=1 drain: {:?}",
        t.elapsed()
    );
    assert_eq!(out.reason, Reason::Paused, "{out:?}");
    assert_eq!(cp.next_index, out.progress.sent);
    let first_leg = with_ret(|s| s.sent.clone());
    assert_eq!(first_leg.len() as u64, cp.next_index);

    // Новая попытка: свой handle и новый attempt_id.
    let (io2, _) = engine_pair(open_pair(&api));
    let h2 = Engine::resume(
        p.clone(),
        cp.clone(),
        io2,
        EngineOptions::new([1; 16], [3; 16]),
    )
    .unwrap();
    let (out2, _) = finish(h2);
    assert_eq!(out2.reason, Reason::Completed, "{out2:?}");
    let all = with_ret(|s| s.sent.clone());
    assert_eq!(
        all.len() as u64,
        PROBES,
        "exactly one send per probe across both legs"
    );
    for (i, f) in all.iter().enumerate() {
        assert_eq!(*f, syn_frame(&p, i), "probe {i}");
    }
}

#[test]
fn rx_loss_and_stats_errors_fail_the_run_and_keep_the_results() {
    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let p = plan(1e6, 1);
    let (io, _) = engine_pair(open_pair(&api));
    with(|s| s.stats_drop = 3); // потери очереди NPF
    let (out, events) = finish(start(&p, io, 2));
    assert!(
        matches!(
            out.reason,
            Reason::Failed(FailReason::RxLoss { kernel_drops: 3 })
        ),
        "{out:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );

    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let (io, _) = engine_pair(open_pair(&api));
    // После первого успешного чтения каждое следующее падает (и итоговое тоже).
    with(|s| {
        s.stats_script.push_back(Ok(0));
        s.stats_script.extend(std::iter::repeat_n(Err(-3), 50));
    });
    let (out, _) = finish(start(&p, io, 2));
    assert!(
        matches!(out.reason, Reason::Failed(FailReason::RxError(ref m)) if m.contains("code -3")),
        "{out:?}"
    );
    assert_eq!(out.rx_health.kernel_drops, None, "never a cached zero");
}

struct PanicTx {
    inner: Box<dyn Tx>,
    at: usize,
    n: usize,
}
impl Tx for PanicTx {
    fn send(&mut self, frame: &[u8], t: Duration) -> Result<SendStatus, IoError> {
        if self.n == self.at {
            panic!("injected tx panic");
        }
        self.n += 1;
        self.inner.send(frame, t)
    }
}

#[test]
fn a_worker_panic_ends_the_run_and_closes_every_handle() {
    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let p = plan(1e6, 1);
    let (io, stats) = engine_pair(open_pair(&api));
    let io = AdapterPair {
        tx: Box::new(PanicTx {
            inner: io.tx,
            at: 2,
            n: 0,
        }),
        rx: io.rx,
    };
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(
        out.reason,
        Reason::Failed(FailReason::WorkerPanicked),
        "{out:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    assert_eq!(with_ret(|s| s.send_calls), 2);
    assert_eq!(
        count("close"),
        2,
        "unwinding closed the TX handle, RX closed normally"
    );
    assert_eq!(stats.snapshot().tx_sent, 2);
    drop(api);
    assert_eq!(count("unload"), 1);
}

// ---------- маршрутизация по handle ----------

fn hcalls(key: &str) -> usize {
    with_ret(|s| s.per_handle.get(key).copied().unwrap_or(0))
}

#[test]
fn rx_and_stats_hit_only_the_rx_handle_sends_only_the_tx_handle_and_each_closes_once() {
    // handle 1 = TX, handle 2 = RX (см. open_configures_two_handles_...).
    reset(|s| s.next_script.push_back(NextStep::Frame(peer_frame(60))));
    let api = good_api();
    let mut a = open_pair(&api);
    let mut b = buf();
    assert!(
        a.io.rx
            .recv(&mut b, Duration::from_millis(50))
            .unwrap()
            .is_some()
    );
    a.io.rx.health(Duration::from_millis(50)).unwrap();
    let f = own_frame(60);
    a.io.tx.send(&f, Duration::from_millis(50)).unwrap();
    a.io.tx.send(&f, Duration::from_millis(50)).unwrap();

    assert!(hcalls("next_ex:2") >= 1, "RX reads the RX handle");
    assert_eq!(hcalls("next_ex:1"), 0, "RX never reads the TX handle");
    assert!(
        hcalls("stats:2") >= 2,
        "baseline plus health on the RX handle"
    );
    assert_eq!(hcalls("stats:1"), 0, "stats never read from the TX handle");
    assert_eq!(hcalls("send:1"), 2, "sends go to the TX handle");
    assert_eq!(hcalls("send:2"), 0, "nothing is sent on the RX handle");

    drop(a);
    assert_eq!(count("close:1"), 1);
    assert_eq!(count("close:2"), 1);
    assert_eq!(count("close"), 2);
    drop(api);
    let ev = events();
    let unload = pos(&ev, "unload");
    assert!(pos(&ev, "close:1") < unload && pos(&ev, "close:2") < unload);
}

// ---------- пачки через sendqueue ----------

fn frames_of(n: usize) -> Vec<Vec<u8>> {
    // Разные длины: каждая запись имеет свой размер, граница видна.
    (0..n).map(|i| own_frame(60 + i)).collect()
}

fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(Vec::as_slice).collect()
}

const T50: Duration = Duration::from_millis(50);

#[test]
fn the_outcome_is_sent_only_when_every_queued_byte_was_accepted() {
    let all = TxBatch {
        sent: 5,
        rest: SendStatus::Sent,
    };
    let none = TxBatch {
        sent: 0,
        rest: SendStatus::Uncertain,
    };
    assert_eq!(batch_outcome(5, 400, 400), all, "full");
    // Меньше, ноль (НЕ «ничего не отправлено»), больше: вся пачка Uncertain.
    for bytes in [399, 300, 1, 0, 401, u32::MAX] {
        assert_eq!(batch_outcome(5, 400, bytes), none, "bytes {bytes}");
    }
}

#[test]
fn a_full_transmit_is_sent_exactly_n_and_counts_one_batch() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(5);
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 5,
            rest: SendStatus::Sent
        }
    );
    let s = a.stats.snapshot();
    assert_eq!(
        (s.tx_sent, s.tx_uncertain, s.tx_errors, s.tx_would_block),
        (5, 0, 0, 0)
    );
    assert_eq!((s.tx_batches, s.tx_batch_max), (1, 5));
    with(|s| {
        assert_eq!(s.transmit_calls, 1);
        assert_eq!(s.send_calls, 0, "the queue path never uses pcap_sendpacket");
        assert_eq!(s.sync_seen, vec![0], "sync is never requested");
        assert_eq!(s.sent, fr, "every frame once, in queue order");
    });
    assert_eq!(with_ret(|s| s.per_handle["sendqueue_transmit:1"]), 1);
    assert_eq!(queue_len(0), 0);
}

#[test]
fn a_boundary_partial_is_all_uncertain_and_the_prefix_is_not_counted() {
    // Спайк: драйвер принимает префикс по границе, но счёт байт ему не верен
    // (при отвергнутой записи он возвращает 0), поэтому префикс не засчитывается.
    reset(|s| s.transmit_script.push_back(TransmitStep::Boundary(3)));
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(5);
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 0,
            rest: SendStatus::Uncertain
        }
    );
    let s = a.stats.snapshot();
    // tx_sent <= кадров на проводе <= tx_sent + tx_uncertain: здесь 0 <= 3 <= 5.
    assert_eq!((s.tx_sent, s.tx_uncertain), (0, 5));
    assert_eq!((s.tx_batches, s.tx_batch_max), (1, 5));
    with(|s| {
        assert_eq!((s.transmit_calls, s.send_calls), (1, 0), "no retry");
        assert_eq!(s.sent.len(), 3, "the fake delivered the prefix");
    });
    assert_eq!(queue_len(0), 0);
}

#[test]
fn a_straddling_partial_is_all_uncertain() {
    reset(|s| s.transmit_script.push_back(TransmitStep::Straddle(2)));
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(5);
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 0,
            rest: SendStatus::Uncertain
        }
    );
    let s = a.stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_uncertain, s.tx_errors), (0, 5, 0));
    assert_eq!(queue_len(0), 0);
}

#[test]
fn bytes_over_queued_is_all_uncertain() {
    reset(|s| s.transmit_script.push_back(TransmitStep::Over));
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(4);
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 0,
            rest: SendStatus::Uncertain
        }
    );
    let s = a.stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_uncertain), (0, 4));
    assert_eq!(queue_len(0), 0);
}

#[test]
fn nothing_accepted_is_all_uncertain_and_the_driver_text_decides_nothing() {
    reset(|s| {
        s.transmit_script.push_back(TransmitStep::Bytes(0));
        s.geterr = std::ffi::CString::new("send buffer is full, would block").unwrap();
    });
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(3);
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 0,
            rest: SendStatus::Uncertain
        }
    );
    let s = a.stats.snapshot();
    assert_eq!((s.tx_uncertain, s.tx_would_block), (3, 0));
}

#[test]
fn one_frame_batches_use_sendpacket_not_the_queue() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(1);
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 1,
            rest: SendStatus::Sent
        }
    );
    with(|s| {
        assert_eq!((s.send_calls, s.transmit_calls), (1, 0));
        assert_eq!(s.sent, fr);
    });
    let s = a.stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_batches, s.tx_batch_max), (1, 0, 0));

    // Отказ драйвера на одном кадре: Uncertain, sent 0, без повтора.
    with(|s| s.send_rcs.push_back(-1));
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(
        out,
        TxBatch {
            sent: 0,
            rest: SendStatus::Uncertain
        }
    );
    assert_eq!(with_ret(|s| (s.send_calls, s.transmit_calls)), (2, 0));
    assert_eq!(a.stats.snapshot().tx_uncertain, 1);
}

#[test]
fn a_bad_length_anywhere_in_the_batch_sends_nothing_and_is_an_io_error() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let good = own_frame(60);
    let mut errors = 0;
    for bad in [0usize, MIN_TX_FRAME - 1, MAX_TX_FRAME + 1, 9000] {
        let bad_frame = vec![0u8; bad];
        for at in [0usize, 1, 2] {
            let mut batch: Vec<&[u8]> = vec![&good, &good, &good];
            batch[at] = &bad_frame;
            let e = a.io.tx.send_batch(&batch, T50).unwrap_err();
            errors += 1;
            assert!(e.message.contains("nothing was sent"), "{bad}@{at}: {e:?}");
        }
    }
    with(|s| {
        assert_eq!((s.send_calls, s.transmit_calls), (0, 0));
        assert!(s.sent.is_empty());
    });
    // Ничего не поставлено в очередь: длины проверены раньше постановки.
    assert_eq!(queue_len(0), 0);
    let s = a.stats.snapshot();
    assert_eq!((s.tx_errors, s.tx_sent, s.tx_batches), (errors, 0, 0));
    // Пустая пачка это тоже IoError, адаптер остался рабочим.
    assert!(a.io.tx.send_batch(&[], T50).is_err());
    let fr = frames_of(2);
    assert_eq!(a.io.tx.send_batch(&refs(&fr), T50).unwrap().sent, 2);
}

#[test]
fn an_oversized_batch_is_refused_before_queueing() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(TX_BATCH_FRAMES + 1);
    let e = a.io.tx.send_batch(&refs(&fr), T50).unwrap_err();
    assert!(e.message.contains("nothing was sent"), "{e:?}");
    with(|s| assert_eq!((s.send_calls, s.transmit_calls), (0, 0)));
    assert_eq!(queue_len(0), 0);
    // Ровно TX_BATCH_FRAMES максимальных кадров помещается в очередь.
    let big = vec![own_frame(MAX_TX_FRAME); TX_BATCH_FRAMES];
    let out = a.io.tx.send_batch(&refs(&big), T50).unwrap();
    assert_eq!(out.sent, TX_BATCH_FRAMES);
    assert_eq!(with_ret(|s| s.transmit_calls), 1);
    assert_eq!(
        TX_QUEUE_BYTES as usize,
        TX_BATCH_FRAMES * (SENDQUEUE_RECORD_HEADER + MAX_TX_FRAME)
    );
}

#[test]
fn queue_full_is_an_io_error_and_nothing_was_transmitted() {
    reset(|s| s.queue_full_at = Some(3));
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(5);
    let e = a.io.tx.send_batch(&refs(&fr), T50).unwrap_err();
    assert!(
        e.message
            .contains("sendqueue refused a frame that fits the allocated queue"),
        "{e:?}"
    );
    with(|s| assert_eq!((s.transmit_calls, s.send_calls), (0, 0)));
    assert_eq!(queue_len(0), 0, "the partly filled queue was emptied");
    let s = a.stats.snapshot();
    assert_eq!(
        (s.tx_errors, s.tx_sent, s.tx_uncertain, s.tx_batches),
        (1, 0, 0, 0)
    );
}

#[test]
fn queue_is_empty_after_every_outcome() {
    use TransmitStep::*;
    let steps = [All, Boundary(2), Straddle(2), Over, Bytes(0), Bytes(1)];
    reset(|s| s.transmit_script.extend(steps));
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(5);
    for step in steps {
        a.io.tx.send_batch(&refs(&fr), T50).unwrap();
        assert_eq!(queue_len(0), 0, "after {step:?}");
    }
    // Ошибочные исходы тоже.
    assert!(a.io.tx.send_batch(&[], T50).is_err());
    assert_eq!(queue_len(0), 0);
    with(|s| s.queue_full_at = Some(1));
    assert!(a.io.tx.send_batch(&refs(&fr), T50).is_err());
    assert_eq!(queue_len(0), 0);
}

#[test]
fn open_allocates_one_queue_after_the_tx_handle_and_before_rx() {
    reset(|_| {});
    let api = good_api();
    let a = open_pair(&api);
    let ev = events();
    let creates: Vec<usize> = ev
        .iter()
        .enumerate()
        .filter(|(_, e)| *e == "create")
        .map(|(i, _)| i)
        .collect();
    let alloc = pos(&ev, &format!("sendqueue_alloc:{TX_QUEUE_BYTES}"));
    assert!(creates[0] < alloc && alloc < creates[1], "{ev:?}");
    assert_eq!(
        ev.iter()
            .filter(|e| e.starts_with("sendqueue_alloc"))
            .count(),
        1
    );
    drop(a);
}

#[test]
fn sendqueue_is_destroyed_before_the_tx_handle_closes() {
    reset(|_| {});
    let api = good_api();
    let a = open_pair(&api);
    drop(a);
    drop(api);
    let ev = events();
    let destroy = pos(&ev, "sendqueue_destroy");
    let close_tx = pos(&ev, "close:1");
    assert!(destroy < close_tx, "{ev:?}");
    assert!(close_tx < pos(&ev, "unload"), "{ev:?}");
    assert_eq!(count("sendqueue_destroy"), 1);
}

#[test]
fn transmit_longer_than_fifty_ms_is_counted_over_budget() {
    reset(|s| s.transmit_sleep = Duration::from_millis(60));
    let api = good_api();
    let mut a = open_pair(&api);
    let fr = frames_of(3);
    // Результат не меняется: transmit не отменяем, длительность только считается.
    let out = a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(out.sent, 3);
    let s = a.stats.snapshot();
    assert_eq!((s.tx_over_budget, s.tx_batches), (1, 1));
    with(|s| s.transmit_sleep = Duration::from_millis(70));
    a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    assert_eq!(a.stats.snapshot().tx_over_budget, 2);
}

#[test]
fn a_single_send_longer_than_fifty_ms_is_counted_over_budget() {
    reset(|s| s.send_sleep = Duration::from_millis(60));
    let api = good_api();
    let mut a = open_pair(&api);
    assert_eq!(a.io.tx.send(&own_frame(60), T50).unwrap(), SendStatus::Sent);
    let s = a.stats.snapshot();
    assert_eq!((s.tx_over_budget, s.tx_batches, s.tx_sent), (1, 0, 1));
}

#[test]
fn net_stats_batches_and_max_survive_closing() {
    reset(|_| {});
    let api = good_api();
    let mut a = open_pair(&api);
    let stats = a.stats.clone();
    for n in [3, 7, 2] {
        let fr = frames_of(n);
        a.io.tx.send_batch(&refs(&fr), T50).unwrap();
    }
    // Один кадр это не пачка.
    let one = frames_of(1);
    a.io.tx.send_batch(&refs(&one), T50).unwrap();
    drop(a);
    let s = stats.snapshot();
    assert_eq!((s.tx_batches, s.tx_batch_max, s.tx_sent), (3, 7, 13));
}

#[test]
fn tx_mode_is_sendqueue_with_the_cap() {
    reset(|_| {});
    let api = good_api();
    let a = open_pair(&api);
    assert_eq!(
        a.tx_mode,
        TxMode::SendQueue {
            max_batch: TX_BATCH_FRAMES
        }
    );
    assert_eq!(a.io.tx.max_batch(), TX_BATCH_FRAMES);
}

/// Кадры плана по порядку курсора.
fn plan_frames(p: &ReadyPlan) -> Vec<Vec<u8>> {
    let mut c = ProbeCursor::new(p, 0).unwrap();
    let mut v = Vec::new();
    while let Some(probe) = c.current() {
        v.push(probe.frame.clone());
        c.advance_sent();
    }
    v
}

fn big_plan(rate: f64, cidr: &str) -> ReadyPlan {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), cidr).unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    let cfg = ScanConfig {
        targets: m,
        seed: 0x1234_5678_9abc,
        max_rate: rate,
        wait_secs: 1,
        ..ScanConfig::default()
    };
    let eff = validate(&cfg, Operation::Scan).unwrap();
    ReadyPlan::new(eff, binding()).unwrap()
}

#[test]
fn engine_scan_through_fake_sendqueue_completes_with_exactly_one_advance_per_sent() {
    reset(|_| {});
    syn_ack_responder();
    let api = good_api();
    let p = big_plan(1e6, "10.0.0.0/22"); // 2048 проб: несколько пачек
    let total = plan_frames(&p).len() as u64;
    let (io, stats) = engine_pair(open_pair(&api));
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(out.reason, Reason::Completed, "{out:?}");
    assert_eq!(out.progress.sent, total);
    assert_eq!(out.progress.next_index, total);
    assert_eq!(replies(&events).len() as u64, total);
    let s = stats.snapshot();
    assert_eq!((s.tx_sent, s.tx_uncertain, s.tx_errors), (total, 0, 0));
    assert!(s.tx_batches > 0, "the batched path was used: {s:?}");
    assert!(s.tx_batch_max as usize <= TX_BATCH_FRAMES);
    with(|st| {
        assert_eq!(st.sent, plan_frames(&p), "plan order, each once");
        assert_eq!(
            st.send_calls as u64 + st.transmitted.iter().map(|b| b.len() as u64).sum::<u64>(),
            total
        );
        assert!(st.queues.is_empty(), "no queue outlives the adapter");
    });
}

#[test]
fn engine_partial_transmit_fails_uncertain_without_checkpoint_or_more_batches() {
    // Первая же передача пачкой принимает 1 запись и обрывается на границе.
    reset(|s| {
        s.transmit_script
            .extend(std::iter::repeat_n(TransmitStep::Boundary(1), 64))
    });
    let api = good_api();
    let p = big_plan(1e6, "10.0.0.0/22");
    let (io, stats) = engine_pair(open_pair(&api));
    let (out, events) = finish(start(&p, io, 2));
    assert_eq!(
        out.reason,
        Reason::Failed(FailReason::TxUncertain),
        "{out:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::CheckpointReady { .. }))
    );
    std::thread::sleep(Duration::from_millis(100));
    let (calls, delivered, singles) = with_ret(|s| {
        (
            s.transmit_calls,
            s.transmitted.iter().map(Vec::len).sum::<usize>(),
            s.send_calls,
        )
    });
    // Ровно одна неудачная передача и ничего после неё.
    assert_eq!(calls, 1, "no more batches after the partial one");
    let s = stats.snapshot();
    assert_eq!(s.tx_batches, 1);
    // Одиночные отправки до пачки (разгон троттлера) допустимы; префикс
    // пачки (доставленный фейком) не засчитан.
    assert!(delivered > 0);
    assert_eq!(out.progress.sent as usize, singles);
    assert_eq!(s.tx_sent, out.progress.sent);
    assert_eq!(out.progress.next_index, out.progress.sent);
    assert!(s.tx_uncertain > 0);
}

#[test]
fn engine_stop_between_batches_sends_nothing_afterwards() {
    reset(|s| s.transmit_sleep = Duration::from_millis(10));
    let api = good_api();
    let p = big_plan(1e6, "10.0.0.0/16"); // 131072 проб: заведомо не закончится
    let (io, stats) = engine_pair(open_pair(&api));
    let h = start(&p, io, 2);
    while h.progress().sent < 2 {
        std::thread::sleep(Duration::from_millis(2));
    }
    let t = Instant::now();
    h.stop();
    let (out, _) = finish(h);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(out.reason, Reason::Stopped, "{out:?}");
    let at_join = with_ret(|s| (s.transmit_calls, s.send_calls));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        with_ret(|s| (s.transmit_calls, s.send_calls)),
        at_join,
        "a worker sent after Stop"
    );
    let delivered = with_ret(|s| s.sent.len() as u64);
    assert_eq!(
        delivered, out.progress.sent,
        "the cursor equals what the driver took"
    );
    assert_eq!(stats.snapshot().tx_sent, delivered);
    assert_eq!(with_ret(|s| s.queues.len()), 0);
}

/// Только `send`: `max_batch() == 1`, как у прежнего одиночного пути.
struct SingleOnly(Box<dyn Tx>);
impl Tx for SingleOnly {
    fn send(&mut self, frame: &[u8], t: Duration) -> Result<SendStatus, IoError> {
        self.0.send(frame, t)
    }
}

#[test]
fn pause_resume_through_batches_has_no_gap_or_duplicate() {
    // Базовая линия: тот же план по одному кадру (max_batch 1).
    reset(|_| {});
    let api = good_api();
    let p = big_plan(1e6, "10.0.0.0/20"); // 8192 пробы
    let expected = plan_frames(&p);
    let io = engine_pair(open_pair(&api)).0;
    let io = AdapterPair {
        tx: Box::new(SingleOnly(io.tx)),
        rx: io.rx,
    };
    let (out, _) = finish(start(&p, io, 2));
    assert_eq!(out.reason, Reason::Completed, "{out:?}");
    let baseline = with_ret(|s| s.sent.clone());
    assert_eq!(baseline, expected);
    assert_eq!(with_ret(|s| s.transmit_calls), 0);

    // Пачками, с паузой посередине.
    reset(|s| s.transmit_sleep = Duration::from_millis(20));
    let (io, _) = engine_pair(open_pair(&api));
    let h = start(&p, io, 3);
    while h.progress().sent < 1 {
        std::thread::sleep(Duration::from_millis(2));
    }
    h.pause();
    while h.outcome().is_none() {
        std::thread::sleep(Duration::from_millis(2));
    }
    let cp = h.checkpoint().expect("a paused run carries a checkpoint");
    let (out, _) = finish(h);
    assert_eq!(out.reason, Reason::Paused, "{out:?}");
    let first_leg = with_ret(|s| s.sent.clone());
    assert_eq!(first_leg.len() as u64, cp.next_index);
    assert!(first_leg.len() < expected.len(), "paused before the end");
    assert_eq!(cp.next_index, out.progress.sent);

    with(|s| s.transmit_sleep = Duration::ZERO);
    let (io2, _) = engine_pair(open_pair(&api));
    let h2 = Engine::resume(p.clone(), cp, io2, EngineOptions::new([1; 16], [4; 16])).unwrap();
    let (out2, _) = finish(h2);
    assert_eq!(out2.reason, Reason::Completed, "{out2:?}");
    let all = with_ret(|s| s.sent.clone());
    assert_eq!(
        all.len(),
        expected.len(),
        "one send per probe over both legs"
    );
    assert!(
        all == baseline,
        "batched order differs from the max_batch 1 order"
    );
}
