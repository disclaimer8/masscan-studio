//! Идентичность задания и отказ resume при любом её изменении. Офлайн.

mod common;

use common::*;
use rmasscan_core::config::{Operation, ScanConfig, validate};
use rmasscan_core::massip::MassIp;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_core::scan::Shard;
use rmasscan_core::targets::{add_target_string, parse_ports};
use rmasscan_engine::identity::{canonical_job_bytes, digest_bytes};
use rmasscan_engine::{
    CHECKPOINT_FORMAT_VERSION, Checkpoint, CheckpointError, ENGINE_ALGORITHM_VERSION, StartError,
    job_digest,
};

#[derive(Clone)]
struct Spec {
    targets: &'static str,
    ports: &'static str,
    excludes: Option<&'static str>,
    exclude_ports: Option<&'static str>,
    seed: u64,
    rate: f64,
    wait: u32,
    binding: AdapterBinding,
}

fn base() -> Spec {
    Spec {
        targets: "10.0.0.0/29",
        ports: "80,443",
        excludes: None,
        exclude_ports: None,
        seed: SEED,
        rate: 1_000_000.0,
        wait: 3,
        binding: AdapterBinding {
            interface_id: "fake0".into(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: [0, 0x11, 0x22, 0x33, 0x44, 0x55],
            next_hop_mac: [0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            source_ports: (40000, 40015),
        },
    }
}

fn cfg(s: &Spec) -> ScanConfig {
    let mut m = MassIp::new();
    add_target_string(m.ipv4_mut(), s.targets).unwrap();
    parse_ports(m.ports_mut(), s.ports).unwrap();
    let mut ex = MassIp::new();
    if let Some(e) = s.excludes {
        add_target_string(ex.ipv4_mut(), e).unwrap();
    }
    if let Some(e) = s.exclude_ports {
        parse_ports(ex.ports_mut(), e).unwrap();
    }
    ScanConfig {
        targets: m,
        excludes: ex,
        seed: s.seed,
        max_rate: s.rate,
        wait_secs: s.wait,
        ..ScanConfig::default()
    }
}

fn build(s: &Spec) -> ReadyPlan {
    ReadyPlan::new(
        validate(&cfg(s), Operation::Scan).unwrap(),
        s.binding.clone(),
    )
    .unwrap()
}

fn variants() -> Vec<(&'static str, Spec)> {
    let b = base();
    let mut v: Vec<(&'static str, Spec)> = Vec::new();
    let mut add = |name, f: &dyn Fn(&mut Spec)| {
        let mut s = b.clone();
        f(&mut s);
        v.push((name, s));
    };
    add("targets", &|s| s.targets = "10.0.0.0/28");
    add("targets-shifted", &|s| s.targets = "10.0.1.0/29");
    add("ports", &|s| s.ports = "80,444");
    add("ports-extra", &|s| s.ports = "80,443,8080");
    add("exclude-ip", &|s| s.excludes = Some("10.0.0.3"));
    add("exclude-port", &|s| s.exclude_ports = Some("443"));
    add("seed", &|s| s.seed = SEED + 1);
    add("rate", &|s| s.rate = 999_999.0);
    add("wait", &|s| s.wait = 4);
    add("iface", &|s| s.binding.interface_id = "fake1".into());
    add("link", &|s| s.binding.link_type = LinkType::Raw);
    add("src-ip", &|s| s.binding.source_ipv4 = IP_ME + 1);
    add("src-mac", &|s| s.binding.source_mac[5] ^= 1);
    add("next-hop", &|s| s.binding.next_hop_mac[0] ^= 1);
    add("src-port-first", &|s| {
        s.binding.source_ports = (40016, 40031)
    });
    add("src-port-width", &|s| {
        s.binding.source_ports = (40000, 40007)
    });
    v
}

#[test]
fn every_identity_field_changes_the_digest() {
    let d0 = job_digest(&build(&base()));
    let mut seen = vec![d0];
    for (name, s) in variants() {
        let d = job_digest(&build(&s));
        assert_ne!(d, d0, "{name}: digest unchanged");
        assert!(!seen.contains(&d), "{name}: collides with another variant");
        seen.push(d);
    }
}

#[test]
fn every_identity_field_rejects_resume_before_the_first_send() {
    let p0 = build(&base());
    let cp = first_leg(&p0, 5, 1, 10)
        .checkpoint
        .expect("pause checkpoint");
    for (name, s) in variants() {
        let err = resume_rejected(&build(&s), &cp, 11);
        assert!(
            matches!(err, StartError::Checkpoint(CheckpointError::JobMismatch)),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn retries_shard_and_rounds_are_part_of_the_encoding() {
    // ReadyPlan v1 принимает только retries 0 / shard 1/1 / rounds 14, поэтому
    // проверяем кодировку напрямую.
    let s = base();
    let binding = s.binding.clone();
    let enc = |f: &dyn Fn(&mut ScanConfig)| {
        let mut c = cfg(&s);
        f(&mut c);
        canonical_job_bytes(&validate(&c, Operation::Scan).unwrap(), &binding)
    };
    let b0 = enc(&|_| {});
    assert_ne!(b0, enc(&|c| c.retries = 1));
    assert_ne!(b0, enc(&|c| c.shard = Shard { one: 1, of: 2 }));
    assert_ne!(b0, enc(&|c| c.shard = Shard { one: 2, of: 2 }));
    assert_ne!(b0, enc(&|c| c.blackrock_rounds = 4));
}

#[test]
fn equivalent_spellings_normalize_to_the_same_digest() {
    let d0 = job_digest(&build(&base()));
    let mut a = base();
    a.targets = "10.0.0.0-10.0.0.7";
    a.ports = "443,80";
    assert_eq!(job_digest(&build(&a)), d0);
    let mut b = base();
    b.targets = "10.0.0.4/30,10.0.0.0/30";
    assert_eq!(job_digest(&build(&b)), d0);
}

#[test]
fn encoding_is_framed_and_versioned() {
    let p = build(&base());
    let bytes = canonical_job_bytes(p.effective(), p.binding());
    assert_eq!(&bytes[..8], b"RMSCNJOB");
    assert_eq!(&bytes[8..12], &ENGINE_ALGORITHM_VERSION.to_be_bytes());
    // Первый список (target ipv4) начинается со счётчика и пары begin/end.
    assert_eq!(&bytes[12..16], &1u32.to_be_bytes());
    assert_eq!(&bytes[16..20], &0x0a00_0000u32.to_be_bytes());
    assert_eq!(&bytes[20..24], &0x0a00_0007u32.to_be_bytes());
    assert_eq!(digest_bytes(&bytes), job_digest(&p));
    // Склейка строк неоднозначной быть не может: interface_id с длиной.
    let mut x = base();
    x.binding.interface_id = "ab".into();
    let mut y = base();
    y.binding.interface_id = "a".into();
    let bx = canonical_job_bytes(build(&x).effective(), &x.binding);
    let by = canonical_job_bytes(build(&y).effective(), &y.binding);
    assert_eq!(bx.len(), by.len() + 1);
    assert_ne!(bx, by);
}

#[test]
fn digest_is_pinned_for_the_reference_job() {
    // Фиксирует кодировку и ENGINE_ALGORITHM_VERSION = 1. Если тест упал, а
    // вы не меняли формат, сломана совместимость сохранённых заданий; если
    // меняли, то повысьте ENGINE_ALGORITHM_VERSION и обновите значение.
    // Комментарии и правки кода без смены формата дайджест не меняют.
    let d = job_digest(&build(&base()));
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PINNED);
}

const PINNED: &str = "f51d122b3a2cc0377130e70d6b1d7e9d90a6e901062c6a65bb81b8c895695dc5";

fn mapped(reverse: bool, changed_ip: Option<u32>) -> ReadyPlan {
    let s = base();
    let mut entries: Vec<_> = (0x0a00_0000..=0x0a00_0007)
        .map(|ip| (ip, [2, 1, 2, 3, 4, ip as u8 + 1]))
        .collect();
    if reverse {
        entries.reverse();
    }
    let mut map: std::collections::BTreeMap<_, _> = entries.into_iter().collect();
    if let Some(ip) = changed_ip {
        map.get_mut(&ip).unwrap()[5] ^= 0x10;
    }
    ReadyPlan::with_destinations(validate(&cfg(&s), Operation::Scan).unwrap(), s.binding, map)
        .unwrap()
}

#[test]
fn mapped_identity_is_canonical_and_includes_every_mac() {
    let p = mapped(false, None);
    let digest = job_digest(&p);
    assert_eq!(digest, job_digest(&mapped(true, None)));
    assert_ne!(digest, job_digest(&build(&base())));
    for ip in 0x0a00_0000..=0x0a00_0007 {
        assert_ne!(
            digest,
            job_digest(&mapped(false, Some(ip))),
            "MAC for {ip:#x} omitted"
        );
    }
    // Independently construct the mapped domain around the unchanged legacy encoding.
    let legacy = canonical_job_bytes(p.effective(), p.binding());
    let mut expected = b"RMSCNMAP".to_vec();
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(&(legacy.len() as u64).to_be_bytes());
    expected.extend_from_slice(&legacy);
    expected.extend_from_slice(&8u64.to_be_bytes());
    for (ip, mac) in p.destinations().unwrap() {
        expected.extend_from_slice(&ip.to_be_bytes());
        expected.extend_from_slice(mac);
    }
    assert_eq!(digest, digest_bytes(&expected));
}

#[test]
fn mapped_checkpoint_resumes_same_map_and_rejects_each_changed_mac_before_send() {
    let p = mapped(false, None);
    let cp = first_leg(&p, 5, 1, 10).checkpoint.unwrap();
    let reordered = mapped(true, None);
    let resumed = resume_leg(&reordered, &cp, usize::MAX, 11);
    assert_eq!(resumed.outcome.reason, rmasscan_engine::Reason::Completed);
    for ip in 0x0a00_0000..=0x0a00_0007 {
        let err = resume_rejected(&mapped(false, Some(ip)), &cp, 11);
        assert!(matches!(
            err,
            StartError::Checkpoint(CheckpointError::JobMismatch)
        ));
    }
    let err = resume_rejected(&build(&base()), &cp, 11);
    assert!(matches!(
        err,
        StartError::Checkpoint(CheckpointError::JobMismatch)
    ));
    let legacy_cp = first_leg(&build(&base()), 5, 1, 10).checkpoint.unwrap();
    let err = resume_rejected(&p, &legacy_cp, 11);
    assert!(matches!(
        err,
        StartError::Checkpoint(CheckpointError::JobMismatch)
    ));
}

#[test]
fn legacy_canonical_bytes_remain_pinned() {
    let p = build(&base());
    let bytes = canonical_job_bytes(p.effective(), p.binding());
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        concat!(
            "524d53434e4a4f42",
            "00000001",
            "00000001",
            "0a000000",
            "0a000007",
            "00000002",
            "00000050",
            "00000050",
            "000001bb",
            "000001bb",
            "00000000",
            "00000000",
            "0000123456789abc",
            "412e848000000000",
            "00000000",
            "00000001",
            "00000001",
            "0000000e",
            "00000003",
            "00000005",
            "66616b6530",
            "01",
            "0aff0001",
            "001122334455",
            "665544332211",
            "9c40",
            "9c4f"
        )
    );
    assert_eq!(job_digest(&p), digest_bytes(&bytes));
}

fn good_checkpoint() -> (ReadyPlan, Checkpoint) {
    let p = build(&base());
    let cp = first_leg(&p, 5, 1, 10).checkpoint.unwrap();
    (p, cp)
}

#[test]
fn corrupted_checkpoint_fields_are_rejected() {
    let (p, cp) = good_checkpoint();
    let cases: Vec<(&str, Checkpoint, CheckpointError)> = vec![
        (
            "format",
            Checkpoint {
                format_version: CHECKPOINT_FORMAT_VERSION + 1,
                ..cp.clone()
            },
            CheckpointError::UnsupportedFormat(CHECKPOINT_FORMAT_VERSION + 1),
        ),
        (
            "engine",
            Checkpoint {
                engine_version: ENGINE_ALGORITHM_VERSION + 1,
                ..cp.clone()
            },
            CheckpointError::EngineVersionMismatch(
                ENGINE_ALGORITHM_VERSION + 1,
                ENGINE_ALGORITHM_VERSION,
            ),
        ),
        (
            "scan_id",
            Checkpoint {
                scan_id: [9; 16],
                ..cp.clone()
            },
            CheckpointError::ScanIdMismatch,
        ),
        (
            "digest",
            Checkpoint {
                job_digest: [0; 32],
                ..cp.clone()
            },
            CheckpointError::JobMismatch,
        ),
        (
            "attempt reused",
            Checkpoint {
                attempt_id: [11; 16],
                ..cp.clone()
            },
            CheckpointError::AttemptIdReused,
        ),
        (
            "index == range",
            Checkpoint {
                next_index: PROBES,
                ..cp.clone()
            },
            CheckpointError::AlreadyCompleted(PROBES),
        ),
    ];
    for (name, bad, want) in cases {
        let err = resume_rejected(&p, &bad, 11);
        assert!(
            matches!(&err, StartError::Checkpoint(e) if *e == want),
            "{name}: {err:?}"
        );
    }
    // Индекс за пределами range.
    let beyond = Checkpoint {
        next_index: PROBES + 1,
        ..cp.clone()
    };
    let err = resume_rejected(&p, &beyond, 11);
    assert!(matches!(err, StartError::Plan(_)), "{err:?}");
    // Исходный checkpoint при этом годен.
    let ok = resume_leg(&p, &cp, usize::MAX, 11);
    assert_eq!(ok.outcome.reason, rmasscan_engine::Reason::Completed);
}

#[test]
fn flipping_any_byte_of_the_serialized_checkpoint_is_detected() {
    let (_, cp) = good_checkpoint();
    let bytes = cp.to_bytes();
    assert_eq!(bytes.len(), rmasscan_engine::checkpoint::CHECKPOINT_LEN);
    assert_eq!(Checkpoint::from_bytes(&bytes).unwrap(), cp);
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(
            Checkpoint::from_bytes(&b).is_err(),
            "byte {i} flip accepted"
        );
    }
    assert!(Checkpoint::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(Checkpoint::from_bytes(&[]).is_err());
}

#[test]
fn scan_id_is_preserved_and_attempt_id_is_fresh() {
    let (p, cp) = good_checkpoint();
    assert_eq!(cp.attempt_id, [10; 16]);
    // Тот же attempt_id в новом запуске отвергается.
    let err = resume_rejected(&p, &cp, 10);
    assert!(matches!(
        err,
        StartError::Checkpoint(CheckpointError::AttemptIdReused)
    ));
    // Свежий attempt: scan_id тот же, текущая попытка новая, происхождение
    // отдельно и не выдаётся за текущую.
    let fake = rmasscan_engine::fake::FakeAdapter::new();
    let clock = rmasscan_engine::fake::ManualClock::new();
    let c: std::sync::Arc<dyn rmasscan_core::throttle::Clock + Send + Sync> = clock.clone();
    let h = rmasscan_engine::Engine::resume_with_clock(
        p.clone(),
        cp.clone(),
        fake.pair(),
        options_for(11),
        c,
    )
    .unwrap();
    assert_eq!(h.scan_id(), cp.scan_id);
    assert_eq!(h.attempt_id(), [11; 16]);
    assert_ne!(h.attempt_id(), cp.attempt_id);
    assert_eq!(h.resumed_from_attempt(), Some(cp.attempt_id));
    h.stop();
    h.join().unwrap();
    // Новый (не resume) запуск не имеет происхождения.
    let h = start_real(&p, &rmasscan_engine::fake::FakeAdapter::new());
    assert_eq!(h.resumed_from_attempt(), None);
    h.stop();
    h.join().unwrap();
}
