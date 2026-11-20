//! Страховка рефакторинга `rmasscan-core` (AGPL-3.0, masscan © Robert David Graham): дайджесты потоков зондов и
//! курсоров, `-sL` и transmit, корпусов разборщиков и кадров стека, записанные на неизменённом коде. Каждая задача
//! рефакторинга обязана сохранить их байт в байт; значения в `common/expected_digests.rs` после записи не правятся.
//!
//! Запись (только на базе): `RMASSCAN_PRINT_DIGESTS=1 cargo test --locked -p rmasscan-core --test native_digests --
//! --nocapture` печатает строки `("ключ", "hex"),` в порядке вычисления и ничего не сверяет. Без переменной каждый
//! вычисленный ключ обязан быть в таблице с тем же значением, и лишних ключей у теста в таблице нет.

mod common;
#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/digest.rs"]
mod digest;
#[path = "common/expected_digests.rs"]
mod expected_digests;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use rmasscan_core::config::{EffectiveConfig, Operation, ScanConfig, TcpHeaderOptions, validate};
use rmasscan_core::massip::{MassIp, TargetIp};
use rmasscan_core::packet::LinkType;
use rmasscan_core::payloads::{CookieMutator, PayloadTable};
use rmasscan_core::probe::{
    AdapterBinding, NicBinding, PlanError, Probe, ProbeCursor, ReadyPlan,
    for_each_probe_nic_with_payloads,
};
use rmasscan_core::ranges::RangeList;
use rmasscan_core::ranges6::Range6List;
use rmasscan_core::receive::{ChecksumPolicy, parse_reply_with};
use rmasscan_core::scan::{Shard, list_scan_v46, transmit_scan_flow_v46};
use rmasscan_core::stack::{ConnAddrs, ConnKey, SegmentIn, SegmentOut};
use rmasscan_core::targets::{parse_ports, range_parse_ipv4};
use rmasscan_core::tcp_frame::{TcpFrameBuilder, tcp_segment};
use rmasscan_core::{arp, ndp};

use corpus::XorShift64Star;
use digest::Digest;

// --- таблица ---

/// Сверка с `expected_digests.rs`. Тест владеет ключами по `owns`: каждый его ключ обязан быть в таблице с тем же
/// значением, а каждый его ключ таблицы обязан быть вычислен.
struct Recorder {
    print: bool,
    owns: fn(&str) -> bool,
    got: Vec<(String, String)>,
}

impl Recorder {
    fn new(owns: fn(&str) -> bool) -> Self {
        Recorder {
            print: std::env::var_os("RMASSCAN_PRINT_DIGESTS").is_some_and(|v| v == "1"),
            owns,
            got: Vec::new(),
        }
    }

    fn put(&mut self, key: impl Into<String>, d: Digest) {
        let key = key.into();
        assert!((self.owns)(&key), "key {key} belongs to another test");
        self.got.push((key, d.finish()));
    }

    fn finish(self) {
        if self.print {
            // Один вывод на тест: строки разных тестов не перемешиваются.
            let mut s = String::from("\n");
            for (k, v) in &self.got {
                s.push_str(&format!("    (\"{k}\", \"{v}\"),\n"));
            }
            print!("{s}");
            return;
        }
        let mut table = BTreeMap::new();
        for &(k, v) in expected_digests::EXPECTED {
            assert!(
                table.insert(k, v).is_none(),
                "duplicate key {k} in the table"
            );
        }
        let mut problems = Vec::new();
        let mut seen = BTreeSet::new();
        for (k, v) in &self.got {
            if !seen.insert(k.as_str()) {
                problems.push(format!("{k}: computed twice"));
            }
            match table.get(k.as_str()) {
                Some(e) if e == v => {}
                Some(e) => problems.push(format!("{k}: expected {e}, got {v}")),
                None => problems.push(format!("{k}: not in the table (got {v})")),
            }
        }
        for k in table.keys().filter(|k| (self.owns)(k)) {
            if !seen.contains(k) {
                problems.push(format!("{k}: in the table but not computed"));
            }
        }
        assert!(
            problems.is_empty(),
            "{} digest problem(s):\n{}",
            problems.len(),
            problems.join("\n")
        );
    }
}

fn owns_list(k: &str) -> bool {
    ["list/", "transmit/", "big/", "v46/"]
        .iter()
        .any(|p| k.starts_with(p))
}

fn owns_corpus(k: &str) -> bool {
    k.starts_with("corpus/")
}

fn owns_stack(k: &str) -> bool {
    k.starts_with("stack/")
}

fn owns_stream(k: &str) -> bool {
    !owns_list(k) && !owns_corpus(k) && !owns_stack(k)
}

fn d128(d: &mut Digest, v: u128) {
    d.u64(v as u64);
    d.u64((v >> 64) as u64);
}

// --- сценарии ---

const IP_ME: u32 = 0x0aff_0001;
const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
/// Адрес источника IPv6 и MAC IPv6-хопа сценариев `v46_*` (как `v6_nic` в `probe.rs`).
const SRC6: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0002;
const NH6: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x09];
const ALL_TCP_OPTIONS: TcpHeaderOptions = TcpHeaderOptions {
    mss: Some(1460),
    sackok: true,
    wscale: Some(3),
    tsecho: Some(0x1234_5678),
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `ReadyPlan::new_cli_with_payloads` со встроенной таблицей.
    Cli,
    /// `ReadyPlan::new_cli_without_port_checks`: план с портом без построителя зонда.
    NoPortChecks,
    /// `ReadyPlan::with_destinations`: у каждой цели свой MAC; только курсоры.
    StudioMap,
}

struct Scenario {
    name: &'static str,
    eff: EffectiveConfig,
    nics: Vec<NicBinding>,
    kind: Kind,
}

/// Конфигурация как `probe.rs::tests::eff`, но через публичный API: seed 42, rate 100, retries 0, shard 1/1,
/// 14 раундов (умолчания `ScanConfig`), затем `f`.
fn eff(targets: &str, ports: &str, f: impl FnOnce(&mut ScanConfig)) -> EffectiveConfig {
    let mut m = MassIp::new();
    m.add_target_string(targets).unwrap();
    parse_ports(m.ports_mut(), ports).unwrap();
    let mut cfg = ScanConfig {
        targets: m,
        seed: 42,
        ..ScanConfig::default()
    };
    f(&mut cfg);
    validate(&cfg, Operation::Scan).unwrap()
}

/// Адаптер как `probe.rs::tests::range_nic`: адреса `ips` и порты `ports` источника включительно.
fn nic(link: LinkType, ips: (u32, u32), ports: (u16, u16)) -> NicBinding {
    let mut n = NicBinding::from(AdapterBinding {
        interface_id: "test0".to_string(),
        link_type: link,
        source_ipv4: ips.0,
        source_mac: MAC_ME,
        next_hop_mac: MAC_NH,
        source_ports: ports,
    });
    n.source_ipv4_last = ips.1;
    n
}

/// Адаптер с `source_ipv6` и `next_hop_mac_ipv6` (как `probe.rs::tests::v6_nic`).
fn with_v6(mut n: NicBinding) -> NicBinding {
    n.source_ipv6 = Some(SRC6);
    n.next_hop_mac_ipv6 = Some(NH6);
    n
}

fn scenarios() -> Vec<Scenario> {
    use LinkType::{Ethernet, Null, Raw};
    const T: &str = "198.18.0.0/26";
    const P: &str = "80,443";
    const UDP: &str = "U:53,U:161,U:9999";
    const MIXED: &str = "80,U:53,U:9999,S:2905,I:0";
    const V46: &str = "198.18.0.0/28,2001:db8::/124";
    const IPS4: (u32, u32) = (0x0aff_0004, 0x0aff_0007);
    let one = (IP_ME, IP_ME);
    let p1 = (40000, 40000);
    let p4 = (40000, 40003);
    let p16 = (40000, 40015);
    let ttl42 = |c: &mut ScanConfig| c.ttl = Some(42);
    let cli = |name, eff, nics| Scenario {
        name,
        eff,
        nics,
        kind: Kind::Cli,
    };
    let second = {
        let mut n = nic(Ethernet, (0x0aff_0002, 0x0aff_0002), (41000, 41000));
        n.binding.interface_id = "test1".to_string();
        n
    };
    vec![
        cli("tcp_eth", eff(T, P, |_| {}), vec![nic(Ethernet, one, p1)]),
        cli("tcp_null", eff(T, P, |_| {}), vec![nic(Null, one, p1)]),
        cli("tcp_raw", eff(T, P, |_| {}), vec![nic(Raw, one, p1)]),
        cli("tcp_ttl42", eff(T, P, ttl42), vec![nic(Ethernet, one, p1)]),
        cli(
            "tcp_badsum",
            eff(T, P, |c| c.badsum = true),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "tcp_options",
            eff(T, P, |c| c.tcp_opts = ALL_TCP_OPTIONS),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "tcp_null_all",
            eff(T, P, |c| {
                c.ttl = Some(42);
                c.badsum = true;
                c.tcp_opts = ALL_TCP_OPTIONS;
            }),
            vec![nic(Null, one, p1)],
        ),
        cli("udp_eth", eff(T, UDP, ttl42), vec![nic(Ethernet, one, p1)]),
        cli("udp_raw", eff(T, UDP, ttl42), vec![nic(Raw, one, p1)]),
        cli(
            "sctp_eth",
            eff(T, "S:80,S:2905", |_| {}),
            vec![nic(Ethernet, one, p1)],
        ),
        cli("icmp_null", eff(T, "I:0", ttl42), vec![nic(Null, one, p1)]),
        cli(
            "arp_eth",
            eff(T, "I:2", |_| {}),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "mixed_eth",
            eff(T, "80,U:53,S:2905,I:0", |_| {}),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "mixed_src_ports_16",
            eff(T, MIXED, |_| {}),
            vec![nic(Ethernet, one, p16)],
        ),
        cli(
            "mixed_src_ips_4",
            eff(T, MIXED, |_| {}),
            vec![nic(Ethernet, IPS4, p4)],
        ),
        cli(
            "arp_src_ports_16",
            eff(T, "I:2", |_| {}),
            vec![nic(Ethernet, one, p16)],
        ),
        cli(
            "retries2",
            eff(T, P, |c| c.retries = 2),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "shard_2_3",
            eff(T, P, |c| c.shard = Shard { one: 2, of: 3 }),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "resume",
            eff(T, P, |c| {
                c.resume_index = 37;
                c.resume_count = Some(50);
            }),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "two_nics",
            eff(T, P, |_| {}),
            vec![nic(Ethernet, one, p1), second],
        ),
        cli(
            "src_ports_16",
            eff(T, P, |_| {}),
            vec![nic(Ethernet, one, p16)],
        ),
        cli(
            "src_ips_4",
            eff(T, P, |_| {}),
            vec![nic(Ethernet, IPS4, p4)],
        ),
        cli(
            "infinite",
            eff(T, "80", |c| {
                c.infinite = true;
                c.retries = 1;
                c.max_rate = 102.0;
            }),
            vec![nic(Ethernet, one, p1)],
        ),
        cli(
            "v46_eth",
            eff(V46, P, |_| {}),
            vec![with_v6(nic(Ethernet, one, p1))],
        ),
        cli(
            "v46_raw",
            eff(V46, P, |_| {}),
            vec![with_v6(nic(Raw, one, p1))],
        ),
        cli(
            "v46_src_ports_16",
            eff(V46, P, |_| {}),
            vec![with_v6(nic(Ethernet, one, p16))],
        ),
        cli(
            "v46_no_src6",
            eff("198.18.0.0/26,2001:db8::10", P, |c| c.seed = 13),
            vec![nic(Ethernet, one, p1)],
        ),
        Scenario {
            name: "bad_oproto",
            eff: eff(T, "80,O:6", |_| {}),
            nics: vec![nic(Ethernet, one, p1)],
            kind: Kind::NoPortChecks,
        },
        Scenario {
            name: "bad_icmp",
            eff: eff(T, "80,I:1,I:600", |_| {}),
            nics: vec![nic(Ethernet, one, p1)],
            kind: Kind::NoPortChecks,
        },
        Scenario {
            name: "studio_map",
            eff: eff("198.18.0.0/28", P, |_| {}),
            nics: vec![nic(Ethernet, one, p1)],
            kind: Kind::StudioMap,
        },
    ]
}

fn scenario(name: &str) -> Scenario {
    scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"))
}

fn plan(s: &Scenario) -> ReadyPlan {
    match s.kind {
        Kind::Cli => {
            ReadyPlan::new_cli_with_payloads(s.eff.clone(), s.nics.clone(), PayloadTable::builtin())
        }
        Kind::NoPortChecks => ReadyPlan::new_cli_without_port_checks(s.eff.clone(), s.nics.clone()),
        Kind::StudioMap => {
            // 198.18.0.xx -> 02:00:c6:12:00:xx
            let map = (0..16u32)
                .map(|k| (0xc612_0000 + k, [0x02, 0x00, 0xc6, 0x12, 0x00, k as u8]))
                .collect();
            ReadyPlan::with_destinations(s.eff.clone(), s.nics[0].binding.clone(), map)
        }
    }
    .unwrap_or_else(|e| panic!("{}: {e:?}", s.name))
}

// --- потоки ---

/// `for_each_probe_nic_with_payloads` по первому адаптеру; в конце `{:?}` итога.
fn probes_stream(s: &Scenario, d: &mut Digest) -> (Vec<Probe>, Result<ControlFlow<()>, PlanError>) {
    let mut out = Vec::new();
    let r = for_each_probe_nic_with_payloads(&s.eff, &s.nics[0], &PayloadTable::builtin(), |p| {
        d.probe(p);
        out.push(p.clone());
        ControlFlow::Continue(())
    });
    d.text(&format!("{r:?}"));
    (out, r)
}

/// Итог одного курсора: подтверждённые зонды прохода 0, последняя позиция и причина остановки.
struct CursorRun {
    pass0: Vec<Probe>,
    position: u64,
    error: Option<PlanError>,
}

/// `preload(batch)` + `advance_sent_n(len)` до конца; после каждого шага `position()` и `resume_base()`.
fn drain(c: &mut ProbeCursor, batch: usize, d: &mut Digest, out: &mut Vec<Probe>) {
    loop {
        let loaded = c.preload(batch);
        if loaded.is_empty() {
            break;
        }
        for p in loaded {
            d.probe(p);
            out.push(p.clone());
        }
        let k = loaded.len();
        c.advance_sent_n(k);
        d.u64(c.position());
        d.u64(c.resume_base());
    }
}

/// Курсор каждого адаптера: начальные `position()`/`resume_base()`, проход 0, у `--infinite` ещё `advance_pass()`,
/// проход 1 и `repeats()`; в конце `{:?}` `build_error()` и последняя `position()`.
fn cursor_stream(s: &Scenario, plan: &ReadyPlan, batch: usize, d: &mut Digest) -> Vec<CursorRun> {
    let mut runs = Vec::new();
    for n in 0..plan.nics().len() as u32 {
        let mut c = plan.cursor_for_nic(n, None).unwrap();
        d.u64(c.position());
        d.u64(c.resume_base());
        let mut pass0 = Vec::new();
        drain(&mut c, batch, d, &mut pass0);
        if s.eff.infinite() {
            let again = c.advance_pass();
            assert!(again, "{}: the second pass starts", s.name);
            d.u32(u32::from(again));
            drain(&mut c, batch, d, &mut Vec::new());
            d.u64(c.repeats());
        }
        let error = c.build_error();
        d.text(&format!("{error:?}"));
        d.u64(c.position());
        runs.push(CursorRun {
            pass0,
            position: c.position(),
            error,
        });
    }
    runs
}

/// Кортежи `transmit_scan_flow_v46` `(i, repeats, xxx, target, port)` и `{:?}` итога.
#[allow(clippy::too_many_arguments)]
fn transmit_tuples(
    m: &MassIp,
    seed: u64,
    shard: Shard,
    nic_count: u32,
    nic_index: u32,
    resume: (u64, Option<u64>),
    retries: u32,
    rate: f64,
    d: &mut Digest,
) {
    let r = transmit_scan_flow_v46(
        m,
        seed,
        14,
        shard,
        nic_count,
        nic_index,
        resume.0,
        resume.1,
        retries,
        rate,
        |i, repeats, xxx, target, port| {
            d.u64(i);
            d.u64(repeats);
            d.u64(xxx);
            d.target(target);
            d.u32(port);
            ControlFlow::<()>::Continue(())
        },
    );
    d.text(&format!("{r:?}"));
}

/// Поток transmit сценария: кортежи каждого адаптера.
fn transmit_stream(s: &Scenario, d: &mut Digest) {
    let e = &s.eff;
    assert_eq!(e.blackrock_rounds(), 14);
    let count = s.nics.len() as u32;
    for n in 0..count {
        transmit_tuples(
            e.massip(),
            e.seed(),
            e.shard(),
            count,
            n,
            (e.resume_index(), e.resume_count()),
            e.retries(),
            e.max_rate(),
            d,
        );
    }
}

fn probe_build(e: PlanError) -> Option<PlanError> {
    Some(PlanError::ProbeBuild(Box::new(e)))
}

#[test]
fn stream_digests_match_base() {
    let mut rec = Recorder::new(owns_stream);
    for s in scenarios() {
        let plan = plan(&s);
        let probes = (s.kind != Kind::StudioMap).then(|| {
            let mut d = Digest::new();
            let r = probes_stream(&s, &mut d);
            rec.put(format!("{}/probes", s.name), d);
            r
        });
        let mut d = Digest::new();
        let c1 = cursor_stream(&s, &plan, 1, &mut d);
        rec.put(format!("{}/cursor1", s.name), d);
        let mut d = Digest::new();
        let c64 = cursor_stream(&s, &plan, 64, &mut d);
        rec.put(format!("{}/cursor64", s.name), d);
        if s.kind != Kind::StudioMap {
            let mut d = Digest::new();
            transmit_stream(&s, &mut d);
            rec.put(format!("{}/transmit", s.name), d);
        }

        // Один адаптер: курсор отдаёт ровно поток `for_each_probe` (у `--infinite` только проход 0).
        if let Some((want, _)) = &probes
            && s.nics.len() == 1
        {
            assert_eq!(&c1[0].pass0, want, "{}: cursor1 != probes", s.name);
            assert_eq!(&c64[0].pass0, want, "{}: cursor64 != probes", s.name);
        }

        // Факты базы, на которые опирается задача 5.
        let sent = |r: &[CursorRun]| (r[0].pass0.len(), r[0].position, r[0].error.clone());
        let flow = probes.as_ref().map(|(_, r)| r.clone());
        match s.name {
            "v46_no_src6" => {
                let err = probe_build(PlanError::NoSourceIpv6);
                assert_eq!(sent(&c1), (37, 37, err.clone()), "v46_no_src6 preload(1)");
                assert_eq!(sent(&c64), (37, 38, err), "v46_no_src6 preload(64)");
                assert_eq!(flow, Some(Err(PlanError::NoSourceIpv6)));
            }
            "bad_oproto" | "bad_icmp" => {
                let port_them = if s.name == "bad_oproto" {
                    196870
                } else {
                    197208
                };
                let e = PlanError::PortDoesNotFit {
                    port_them,
                    port_me: 40000,
                };
                assert_eq!(
                    sent(&c1),
                    (1, 1, probe_build(e.clone())),
                    "{} preload(1)",
                    s.name
                );
                assert_eq!(
                    sent(&c64),
                    (1, 2, probe_build(e.clone())),
                    "{} preload(64)",
                    s.name
                );
                assert_eq!(flow, Some(Err(e)));
            }
            _ => {
                for r in c1.iter().chain(&c64) {
                    assert_eq!(r.error, None, "{}: build error", s.name);
                }
                if let Some(f) = flow {
                    assert_eq!(f, Ok(ControlFlow::Continue(())), "{}", s.name);
                }
            }
        }
    }
    rec.finish();
}

// --- `-sL` и transmit ---

const RATES: [f64; 5] = [1.0, 7.0, 40.0, 100.0, 1e8];
const SEEDS: [u64; 4] = [1, 2, 0xffff_ffff, u64::MAX];
const SHARDS: [Shard; 2] = [Shard { one: 1, of: 1 }, Shard { one: 2, of: 3 }];
/// `(nic_count, nic_index)`.
const NICS: [(u32, u32); 2] = [(1, 0), (2, 1)];

/// `n` адресов подряд от `first`, порт 80, после `optimize`.
fn consecutive(first: u32, n: u32) -> MassIp {
    let mut m = MassIp::new();
    m.ipv4_mut().add_range(first, first + (n - 1));
    m.ports_mut().add_range(80, 80);
    m.optimize();
    m
}

/// Пары `(target, port)` `list_scan_v46` (14 раундов, без resume) и `{:?}` итога.
fn list_pairs(m: &MassIp, seed: u64, shard: Shard, retries: u32, rate: f64, d: &mut Digest) {
    let r = list_scan_v46(m, seed, 14, shard, 0, None, retries, rate, |t, port| {
        d.target(t);
        d.u32(port);
    });
    d.text(&format!("{r:?}"));
}

#[test]
fn list_and_transmit_digests_match_base() {
    let mut rec = Recorder::new(owns_list);
    for (ri, &rate) in RATES.iter().enumerate() {
        for seed in SEEDS {
            let (mut list, mut tx) = (Digest::new(), Digest::new());
            for n in 1..=40u32 {
                let m = consecutive(0x0a00_0001, n);
                for retries in [0u32, 2] {
                    for shard in SHARDS {
                        list.u32(n);
                        list.u32(retries);
                        list.u32(shard.one);
                        // `-sL` с retries добавляет `retries * rate` индексов (main-listscan.c:35): при rate 1e8 это
                        // 2e8 строк на комбинацию, и NonTerminating ловит лишь часть из них. Комбинация не идёт.
                        if retries > 0 && rate >= 1e8 {
                            list.text("not listed: retries * rate = 2e8 indices");
                        } else {
                            list_pairs(&m, seed, shard, retries, rate, &mut list);
                        }
                        for (count, index) in NICS {
                            tx.u32(n);
                            tx.u32(retries);
                            tx.u32(shard.one);
                            tx.u32(count);
                            transmit_tuples(
                                &m,
                                seed,
                                shard,
                                count,
                                index,
                                (0, None),
                                retries,
                                rate,
                                &mut tx,
                            );
                        }
                    }
                }
            }
            rec.put(format!("list/r{}/s{seed}", ri + 1), list);
            rec.put(format!("transmit/r{}/s{seed}", ri + 1), tx);
        }
    }

    // Адреса подряд от 10.0.0.0, порт 80, seed 1, 14 раундов, rate 100, retries 0, shard 1/1, один адаптер.
    for n in [1000u32, 1_000_003] {
        let m = consecutive(0x0a00_0000, n);
        let mut d = Digest::new();
        transmit_tuples(&m, 1, Shard::default(), 1, 0, (0, None), 0, 100.0, &mut d);
        list_pairs(&m, 1, Shard::default(), 0, 100.0, &mut d);
        rec.put(format!("big/{n}"), d);
    }

    // IPv4 и IPv6 вместе: seed 42, rate 100, retries {0, 2}, shard {1/1, 2/3}, у transmit адаптеры (1,0) и (2,1).
    let mut m = MassIp::new();
    m.add_target_string("198.18.0.0/28,2001:db8::/126").unwrap();
    parse_ports(m.ports_mut(), "80,443").unwrap();
    m.optimize();
    let (mut list, mut tx) = (Digest::new(), Digest::new());
    for retries in [0u32, 2] {
        for shard in SHARDS {
            list.u32(retries);
            list.u32(shard.one);
            list_pairs(&m, 42, shard, retries, 100.0, &mut list);
            for (count, index) in NICS {
                tx.u32(retries);
                tx.u32(shard.one);
                tx.u32(count);
                transmit_tuples(
                    &m,
                    42,
                    shard,
                    count,
                    index,
                    (0, None),
                    retries,
                    100.0,
                    &mut tx,
                );
            }
        }
    }
    rec.put("v46/list", list);
    rec.put("v46/transmit", tx);
    rec.finish();
}

// --- корпуса ---

/// Дайджест на каждые 500 входов: `corpus/<name>/<k>`.
fn chunked(rec: &mut Recorder, name: &str, count: usize, mut one: impl FnMut(usize, &mut Digest)) {
    assert_eq!(count % 500, 0);
    let mut d = Digest::new();
    for i in 0..count {
        one(i, &mut d);
        if (i + 1) % 500 == 0 {
            rec.put(format!("corpus/{name}/{}", i / 500), std::mem::take(&mut d));
        }
    }
}

fn dump_ranges(d: &mut Digest, l: &RangeList) {
    d.u32(l.len() as u32);
    for r in l.as_slice() {
        d.u32(r.begin);
        d.u32(r.end);
    }
}

fn dump_ranges6(d: &mut Digest, l: &Range6List) {
    d.u32(l.len() as u32);
    for r in l.as_slice() {
        d128(d, r.begin);
        d128(d, r.end);
    }
}

/// Порты таблицы по возрастанию и для каждого порта в 16 битах `get`: нагрузка, `source_port`, `set_cookie`.
fn dump_table(d: &mut Digest, t: &PayloadTable) {
    d.u32(t.len() as u32);
    for port in t.ports() {
        d.u32(port);
        match u16::try_from(port).ok().map(|p| t.get(p)) {
            Some(Some(e)) => {
                d.u32(1);
                d.bytes(&e.payload);
                d.u32(e.source_port);
                d.text(&format!("{:?}", e.set_cookie));
            }
            Some(None) => d.u32(0),
            None => d.u32(2),
        }
    }
}

/// `SegmentIn` по полям (не `{:?}`: тип живёт в `stack.rs`, который меняет 4c).
fn dump_segment(d: &mut Digest, s: Option<SegmentIn<'_>>) {
    let Some(s) = s else {
        d.u32(0);
        return;
    };
    d.u32(1);
    match s.key.addrs {
        ConnAddrs::V4 { local, remote } => {
            d.target(TargetIp::V4(local));
            d.target(TargetIp::V4(remote));
        }
        ConnAddrs::V6 { local, remote } => {
            d.target(TargetIp::V6(local));
            d.target(TargetIp::V6(remote));
        }
    }
    d.u16(s.key.local_port);
    d.u16(s.key.remote_port);
    d.u32(s.seq);
    d.u32(s.ack);
    d.u32(u32::from(s.flags));
    d.u32(u32::from(s.ttl));
    d.bytes(s.payload);
}

const POLICIES: [ChecksumPolicy; 2] = [ChecksumPolicy::Verify, ChecksumPolicy::TrustHardware];

fn corpus_targets(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x7461_7267_6574_7301);
    chunked(rec, "targets", 5000, |_, d| {
        let s = corpus::target_string(&mut rng);
        d.text(&s);
        let mut m = MassIp::new();
        let r = m.add_target_string(&s);
        d.text(&format!("{r:?}"));
        dump_ranges(d, m.ipv4());
        dump_ranges6(d, m.ipv6());
        d.text(&format!("{:?}", range_parse_ipv4(&s)));
    });
}

fn corpus_ports(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x706f_7274_7302);
    chunked(rec, "ports", 5000, |_, d| {
        let s = corpus::port_string(&mut rng);
        d.text(&s);
        let mut l = RangeList::new();
        let r = parse_ports(&mut l, &s);
        d.text(&format!("{r:?}"));
        dump_ranges(d, &l);
    });
}

fn corpus_nmap(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x6e6d_6170_7303);
    chunked(rec, "nmap", 2000, |_, d| {
        let f = corpus::nmap_file(&mut rng);
        d.bytes(&f);
        let mut t = PayloadTable::empty();
        let r = t.load_nmap_payloads_bytes(&f);
        d.text(&format!("{r:?}"));
        dump_table(d, &t);
    });
}

fn corpus_pcap(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x7063_6170_7304);
    chunked(rec, "pcap", 2000, |_, d| {
        let f = corpus::pcap_file(&mut rng);
        d.bytes(&f);
        let mut t = PayloadTable::empty();
        let r = t.load_pcap_payloads(&f);
        d.text(&format!("{r:?}"));
        dump_table(d, &t);
    });
}

fn corpus_snmp(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x736e_6d70_7305);
    let table = PayloadTable::builtin();
    let base = table
        .get(161)
        .expect("builtin SNMP payload")
        .payload
        .to_vec();
    chunked(rec, "snmp", 5000, |_, d| {
        let mut px = corpus::snmp_input(&base, &mut rng);
        let seqno = rng.next_u64() as u32;
        d.bytes(&px);
        d.u32(seqno);
        CookieMutator::Snmp.apply(&mut px, seqno);
        d.bytes(&px);
    });
}

fn corpus_ranges(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x7261_6e67_6573_7306);
    chunked(rec, "ranges", 2000, |_, d| {
        let inp = corpus::ranges_input(&mut rng);
        let mut l = RangeList::new();
        d.u32(inp.adds.len() as u32);
        for &(b, e) in &inp.adds {
            d.u32(b);
            d.u32(e);
            l.add_range(b, e);
        }
        d.u32(u32::from(inp.sort));
        if inp.sort {
            l.sort_and_merge();
        }
        dump_ranges(d, &l);
        match &inp.excludes {
            Some(ex) => {
                let mut x = RangeList::new();
                d.u32(ex.len() as u32 + 1);
                for &(b, e) in ex {
                    d.u32(b);
                    d.u32(e);
                    x.add_range(b, e);
                }
                l.exclude(&mut x);
                dump_ranges(d, &l);
                dump_ranges(d, &x);
            }
            None => d.u32(0),
        }
        let mut vals = Vec::new();
        for r in l.as_slice() {
            for v in [r.begin, r.end] {
                vals.extend([v, v.wrapping_sub(1), v.wrapping_add(1)]);
            }
        }
        vals.extend(&inp.probes);
        for v in vals {
            d.u32(v);
            d.u32(u32::from(l.is_contains(v)));
        }
        l.optimize();
        let count = l.count();
        d.u64(count);
        for i in 0..count.min(4096) {
            d.u32(l.pick(i));
        }
    });
}

fn corpus_ranges6(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x7261_6e67_6536_7307);
    chunked(rec, "ranges6", 2000, |_, d| {
        let inp = corpus::ranges6_input(&mut rng);
        let mut l = Range6List::new();
        d.u32(inp.adds.len() as u32);
        for &(b, e) in &inp.adds {
            d128(d, b);
            d128(d, e);
            l.add(b, e);
        }
        d.u32(u32::from(inp.sort));
        if inp.sort {
            l.sort_and_merge();
        }
        dump_ranges6(d, &l);
        let mut x = Range6List::new();
        d.u32(inp.excludes.len() as u32);
        for &(b, e) in &inp.excludes {
            d128(d, b);
            d128(d, e);
            x.add(b, e);
        }
        d128(d, l.apply_excludes(&x));
        dump_ranges6(d, &l);
        let mut vals = Vec::new();
        for r in l.as_slice() {
            for v in [r.begin, r.end] {
                vals.extend([v, v.wrapping_sub(1), v.wrapping_add(1)]);
            }
        }
        vals.extend(&inp.probes);
        for v in vals {
            d128(d, v);
            d.u32(u32::from(l.is_contains(v)));
        }
        l.optimize();
        let count = l.count_u128();
        d128(d, count);
        for i in 0..count.min(4096) as u64 {
            d128(d, l.pick(i));
        }
    });
}

/// Сценарии, на зонды которых корпус `receive` строит ответы.
const RECEIVE_SCENARIOS: [&str; 7] = [
    "tcp_eth",
    "tcp_null",
    "udp_eth",
    "sctp_eth",
    "icmp_null",
    "arp_eth",
    "v46_eth",
];

fn corpus_receive(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x7265_6365_6976_6508);
    // Пул: ответы на каждый зонд каждого сценария и сам зонд с переставленными адресами.
    let mut ctx: Vec<(LinkType, ReadyPlan)> = Vec::new();
    let mut pool: Vec<(usize, Vec<u8>)> = Vec::new();
    for name in RECEIVE_SCENARIOS {
        let s = scenario(name);
        let link = s.nics[0].binding.link_type;
        let (probes, r) = probes_stream(&s, &mut Digest::new());
        assert_eq!(r, Ok(ControlFlow::Continue(())), "{name}");
        for p in &probes {
            for f in corpus::replies(p, link, s.nics[0].source_ipv6, &mut rng) {
                pool.push((ctx.len(), f));
            }
        }
        ctx.push((link, plan(&s)));
    }
    // Чётный вход как есть, нечётный тот же с 1–3 заменами байтов и иногда обрезкой.
    let mut accepted = vec![0usize; ctx.len()];
    chunked(rec, "receive", 6000, |k, d| {
        let (ci, base) = &pool[(k / 2) % pool.len()];
        let f = if k % 2 == 0 {
            base.clone()
        } else {
            corpus::mutate(base, &mut rng)
        };
        let (link, plan) = &ctx[*ci];
        d.u32(*ci as u32);
        d.bytes(&f);
        for policy in POLICIES {
            let r = parse_reply_with(&f, *link, plan, policy);
            if k % 2 == 0 && policy == ChecksumPolicy::Verify && matches!(r, Ok(Some(_))) {
                accepted[*ci] += 1;
            }
            d.text(&format!("{r:?}"));
        }
        dump_segment(d, tcp_segment(&f, *link, plan));
        d.text(&format!("{:?}", arp::decode(&f)));
        d.text(&format!("{:?}", arp::incoming_request(&f)));
    });
    // Ответы построены верно: приёмник принимает их на каждом сценарии.
    for (name, n) in RECEIVE_SCENARIOS.iter().zip(&accepted) {
        assert!(*n > 0, "{name}: no reply accepted");
    }
}

fn corpus_ndp(rec: &mut Recorder) {
    let mut rng = XorShift64Star::new(0x6e64_7009);
    let s = scenario("v46_eth");
    let plan = plan(&s);
    let (mac, ip6) = (s.nics[0].binding.source_mac, SRC6);
    chunked(rec, "ndp", 2000, |k, d| {
        let base = corpus::ndp_frame(mac, ip6, &mut rng);
        let f = if k % 2 == 0 {
            base
        } else {
            corpus::mutate(&base, &mut rng)
        };
        d.bytes(&f);
        d.text(&format!("{:?}", ndp::decode_neighbor_solicitation(&f)));
        d.text(&format!("{:?}", ndp::decode_neighbor_advertisement(&f)));
        match ndp::answer_neighbor_solicitation(&f, mac, ip6) {
            Some(a) => {
                d.u32(1);
                d.bytes(&a);
            }
            None => d.u32(0),
        }
        for policy in POLICIES {
            d.text(&format!(
                "{:?}",
                parse_reply_with(&f, LinkType::Ethernet, &plan, policy)
            ));
        }
    });
}

#[test]
fn corpus_digests_match_base() {
    let mut rec = Recorder::new(owns_corpus);
    corpus_targets(&mut rec);
    corpus_ports(&mut rec);
    corpus_nmap(&mut rec);
    corpus_pcap(&mut rec);
    corpus_snmp(&mut rec);
    corpus_ranges(&mut rec);
    corpus_ranges6(&mut rec);
    corpus_receive(&mut rec);
    corpus_ndp(&mut rec);
    rec.finish();
}

// --- кадры стека ---

const STACK_FLAGS: [u8; 7] = [0x02, 0x10, 0x12, 0x11, 0x18, 0x04, 0x14];
const STACK_WINDOWS: [Option<u16>; 2] = [None, Some(600)];
const STACK_LENGTHS: [usize; 14] = [0, 1, 2, 5, 6, 7, 13, 59, 60, 61, 512, 1459, 1460, 2000];

/// `build()` по сетке флагов, окон и длин нагрузки; seq и ack из `rng`, нагрузка `(i * 31 + len) as u8`.
fn stack_grid(b: &TcpFrameBuilder, addrs: ConnAddrs, rng: &mut XorShift64Star) -> Digest {
    let mut d = Digest::new();
    for flags in STACK_FLAGS {
        for window in STACK_WINDOWS {
            for len in STACK_LENGTHS {
                let seg = SegmentOut {
                    key: ConnKey {
                        addrs,
                        local_port: 40000,
                        remote_port: 443,
                    },
                    seq: rng.next_u64() as u32,
                    ack: rng.next_u64() as u32,
                    flags,
                    payload: (0..len).map(|i| (i * 31 + len) as u8).collect(),
                    window,
                };
                d.u32(u32::from(flags));
                d.u32(window.map_or(0, |w| 0x1_0000 | u32::from(w)));
                d.u32(seg.seq);
                d.u32(seg.ack);
                d.u32(len as u32);
                d.bytes(&b.build(&seg));
            }
        }
    }
    d
}

#[test]
fn stack_frame_digests_match_base() {
    let mut rec = Recorder::new(owns_stack);
    let v4 = ConnAddrs::V4 {
        local: IP_ME,
        remote: 0xc612_0007,
    };
    let v6 = ConnAddrs::V6 {
        local: SRC6,
        remote: (0x2001_0db8u128 << 96) | 7,
    };
    // IPv6 только на Ethernet и Raw: первые 4 байта кадра IPv6 на Null это `AF_INET6` хоста.
    for (chan, v4_plan, v6_plan) in [
        ("eth", "tcp_eth", Some("v46_eth")),
        ("null", "tcp_null", None),
        ("raw", "tcp_raw", Some("v46_raw")),
    ] {
        let mut rng = XorShift64Star::new(0x7374_6163_6b0a);
        let b = TcpFrameBuilder::from_plan(&plan(&scenario(v4_plan)));
        rec.put(format!("stack/{chan}/v4"), stack_grid(&b, v4, &mut rng));
        if let Some(name) = v6_plan {
            let b = TcpFrameBuilder::from_plan(&plan(&scenario(name)));
            rec.put(format!("stack/{chan}/v6"), stack_grid(&b, v6, &mut rng));
        }
    }
    rec.finish();
}
