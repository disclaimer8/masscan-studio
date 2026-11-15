//! Независимые поведенческие проверки D6-D9; golden-тесты сравнивают все байты с C.
use super::*;
use crate::app_id;

fn forced(app: u16, segments: &[&[u8]]) -> StreamResult {
    banner_stream(&TcpBannerSettings::default(), 9999, Some(app), segments)
}

#[test]
fn ssh_ident_reply_and_kex_blob_per_packet() {
    // C frames one byte early: each nominal length 8 consumes only seven body bytes.
    let data = b"SSH-2.0-x\n\0\0\0\x08\x04\x14abcde\0\0\0\x08\x04\x15abcde";
    let got = forced(app_id::SSH2, &[data]);
    assert_eq!(got.records, [(app_id::SSH2, data.to_vec())]);
    assert_eq!(got.actions.len(), 3);
    assert_eq!(
        got.actions[0],
        StreamAction::Send(b"SSH-2.0-OPENSSH_7.9\r\n".to_vec())
    );
    for a in &got.actions[1..] {
        let StreamAction::Send(b) = a else {
            panic!("KEX send")
        };
        assert_eq!(b.len(), 1248);
        assert_eq!(&b[..6], b"\0\0\x04\x4c\x04\x14");
    }
    assert_eq!(got.actions[1], got.actions[2]);
}

#[test]
fn ssh_error_appends_exactly_one_more_byte() {
    for bad in [0, 0x80, 0xc3, 0x7f] {
        let mut data = b"SSH-2.0-x".to_vec();
        data.extend_from_slice(&[bad, b'A', b'B', b'C']);
        for segs in [vec![data.as_slice()], data.chunks(1).collect()] {
            let got = forced(app_id::SSH1, &segs);
            assert_eq!(got.records, [(app_id::SSH2, data[..11].to_vec())]);
            assert_eq!(got.actions, [StreamAction::Close]);
        }
    }
}

#[test]
fn telnet_replies_once_per_option_ascending() {
    let got = forced(
        app_id::TELNET,
        &[b"\xff\xfd\x20\xff\xfb\x01\xff\xfd\x01\xff\xfb\x20"],
    );
    assert_eq!(
        got.actions,
        [StreamAction::Send(b"\xff\xfc\x01\xff\xfe\x20".to_vec())]
    );
}

#[test]
fn telnet_invalid_appends_exactly_one_more_byte() {
    for cmd in [1, 255] {
        let data = [255, cmd, b'A', b'B', b'C'];
        for segs in [vec![data.as_slice()], data.chunks(1).collect()] {
            let got = forced(app_id::TELNET, &segs);
            assert_eq!(got.records, [(app_id::TELNET, data[..3].to_vec())]);
            assert!(got.actions.is_empty());
        }
    }
}

#[test]
fn vnc_selects_none_even_if_not_offered() {
    let got = banner_stream(
        &TcpBannerSettings::default(),
        5900,
        None,
        &[b"RFB 003.007\n\x01\x02"],
    );
    assert_eq!(
        got.actions,
        [
            StreamAction::Send(b"RFB 003.007\n".to_vec()),
            StreamAction::Send(vec![1, 1])
        ]
    );
    assert_eq!(
        got.records,
        [
            (app_id::VNC_RFB, b"RFB 003.007\n".to_vec()),
            (app_id::VNC_INFO, b"Security types:\n  VNC-chap\n".to_vec())
        ]
    );
}

#[test]
fn vnc_error_reason_length_low_byte() {
    let got = banner_stream(
        &TcpBannerSettings::default(),
        5900,
        None,
        &[b"RFB 003.008\n\0\0\0\x01\x03badTAIL"],
    );
    assert_eq!(
        got.records,
        [
            (app_id::VNC_RFB, b"RFB 003.008\n".to_vec()),
            (app_id::VNC_INFO, b"ERROR: bad".to_vec())
        ]
    );
    assert_eq!(
        got.actions
            .iter()
            .filter(|a| **a == StreamAction::Close)
            .count(),
        2
    );
}

#[test]
fn rdp_labels_and_unknown() {
    for (kind, result, want) in [
        (2, 2, " NLA-supported"),
        (2, 0, " NLA-unused"),
        (3, 5, " NLA-unsupported"),
        (3, 1, " failure"),
    ] {
        let mut data = b"\x03\0\0\x13\x0e\xd0\0\0\x12\x34\0\x02\0\x08\0\0\0\0\0".to_vec();
        data[11] = kind;
        data[15] = result;
        let got = forced(app_id::RDP, &[&data]);
        assert_eq!(got.records, [(app_id::RDP, want.as_bytes().to_vec())]);
        assert!(got.actions.is_empty());
    }
    let got = forced(app_id::RDP, &[b"\x03\0\0\x0c\x07\xe0\0\0\0\0\0X"]);
    assert_eq!(got.records, [(app_id::RDP, b" COTPPDU=unknown".to_vec())]);
}

/// M4 ревью задач 11-13: байт результата CC от 0x80 у C это знаковый сдвиг `c << 24` (`src/proto-tcp-rdp.c:65`,
/// рядом с E1.19); результат `unsigned`, и обычная сборка даёт те же 32 бита, что беззнаковый сдвиг здесь:
/// `0x80000005` это не 5 (` failure`), `0xff000002` несёт бит 2 (` NLA-supported`).
#[test]
fn rdp_high_bit_result_byte_is_unsigned() {
    for (kind, result, want) in [
        (3, [5, 0, 0, 0x80], " failure"),
        (3, [5, 0, 0, 0], " NLA-unsupported"),
        (2, [2, 0, 0, 0xff], " NLA-supported"),
        (2, [0, 0, 0, 0xff], " NLA-unused"),
    ] {
        let mut data = b"\x03\0\0\x13\x0e\xd0\0\0\x12\x34\0\x02\0\x08\0\0\0\0\0".to_vec();
        data[11] = kind;
        data[15..19].copy_from_slice(&result);
        let got = forced(app_id::RDP, &[&data]);
        assert_eq!(
            got.records,
            [(app_id::RDP, want.as_bytes().to_vec())],
            "{result:?}"
        );
    }
}

#[test]
fn rdp_unknown_appends_whole_stream() {
    let good = b"\x03\0\0\x13\x0e\xd0\0\0\x12\x34\0\x02\0\x08\0\x02\0\0\0";
    for tail in [&b"Xtail"[..], b"\x03\0\0\x03tail"] {
        let data = [good.as_slice(), tail].concat();
        for segs in [vec![data.as_slice()], data.chunks(1).collect()] {
            let got = forced(app_id::RDP, &segs);
            assert_eq!(
                got.records,
                [
                    (app_id::RDP, b" NLA-supported".to_vec()),
                    (app_id::HEUR, data.clone())
                ]
            );
        }
    }
    assert!(forced(app_id::RDP, &[b"\x03\0\0\x03"]).records.is_empty());
    assert_eq!(
        forced(app_id::RDP, &[b"X"]).records,
        [(app_id::HEUR, b"X".to_vec())]
    );
}

#[test]
fn binary_parsers_never_panic() {
    let mut rng = TestRng(0x783f_1459);
    for app in [
        app_id::SSH1,
        app_id::SSH2,
        app_id::TELNET,
        app_id::VNC_RFB,
        app_id::RDP,
    ] {
        for _ in 0..1000 {
            let data = (0..512).map(|_| rng.next() as u8).collect::<Vec<_>>();
            let got = forced(
                app,
                &data
                    .chunks(1 + (rng.next() as usize % 31))
                    .collect::<Vec<_>>(),
            );
            assert!(got.records.iter().all(|r| r.1.len() <= 65_536));
        }
    }
}

/// I3 ревью задач 11-13: поток через сессию по сегментам случайной длины 1..=8 с [`Parser::probe`] после каждого
/// сегмента. Возвращает записи и действия; проверяет предел записи и то, что те же записи и действия дают весь поток
/// одним сегментом (Р13: SSH, VNC и RDP от нарезки не зависят ни в записях, ни в действиях).
fn probed(
    rng: &mut TestRng,
    port: u16,
    force: Option<u16>,
    data: &[u8],
    seen: &mut std::collections::BTreeSet<u32>,
) {
    use crate::tcp::app::{ByteBudget, Session};
    let cfg = session::BannerConfig::new(&TcpBannerSettings::default());
    let mut sess = match force {
        Some(app) => cfg.forced(port, app),
        None => cfg.session(port),
    };
    let mut budget = ByteBudget::new(usize::MAX);
    let mut acts = Vec::new();
    let mut segs: Vec<&[u8]> = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (seg, tail) = rest.split_at((1 + rng.below(8)).min(rest.len()));
        sess.parse(seg, &mut budget, &mut acts);
        seen.extend(sess.probe());
        segs.push(seg);
        rest = tail;
    }
    let records = sess.flush(&mut budget);
    assert!(records.iter().all(|r| r.1.len() <= 65_536));
    let whole = banner_stream(&TcpBannerSettings::default(), port, force, &[data]);
    let split = banner_stream(&TcpBannerSettings::default(), port, force, &segs);
    assert_eq!(whole.records, records, "{data:02x?}");
    assert_eq!(split.records, whole.records, "{data:02x?}");
    assert_eq!(split.actions, whole.actions, "{data:02x?}");
}

fn push_be32(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_be_bytes());
}

/// Длина `n`, перекошенная на -3..=3, иногда случайный байт.
fn skewed(rng: &mut TestRng, n: usize) -> u8 {
    if rng.below(8) == 0 {
        return rng.next() as u8;
    }
    u8::try_from((n + rng.below(7)).saturating_sub(3).min(255)).unwrap_or(255)
}

/// SSH: верная строка идентификации (иногда с байтом ошибки), затем пакеты с перекошенной длиной (в том числе первый
/// байт длины от 0x80, E1.19) и кодом KEXINIT, NEWKEYS или любым, иногда случайный хвост.
fn ssh_stream(rng: &mut TestRng) -> Vec<u8> {
    let mut v = [&b"SSH-2.0-"[..], b"SSH-1.99-"][rng.below(2)].to_vec();
    for _ in 0..rng.below(16) {
        v.push(0x20 + rng.below(95) as u8);
    }
    if rng.below(10) == 0 {
        v.push([0, 0x7f, 0x80, 0xc3][rng.below(4)]);
    }
    if rng.below(2) == 0 {
        v.push(b'\r');
    }
    v.push(b'\n');
    for _ in 0..rng.below(5) {
        let body = rng.below(40);
        let len = match rng.below(10) {
            0 => rng.next() as u32,
            1 => 0,
            _ => u32::try_from((body + 2 + rng.below(7)).saturating_sub(3)).unwrap_or(0),
        };
        push_be32(&mut v, len);
        v.push(rng.below(8) as u8);
        v.push([0x14, 0x15, 0x1e, rng.next() as u8][rng.below(4)]);
        v.extend((0..body).map(|_| rng.next() as u8));
    }
    if rng.below(4) == 0 {
        v.extend((0..rng.below(32)).map(|_| rng.next() as u8));
    }
    v
}

/// ServerInit VNC: ширина, высота, 16 байт формата, длина имени (перекошенная, иногда 0) и имя.
fn vnc_server_init(rng: &mut TestRng, v: &mut Vec<u8>) {
    v.extend((0..20).map(|_| rng.next() as u8));
    let name = rng.below(12);
    let len = if rng.below(6) == 0 {
        0
    } else {
        skewed(rng, name)
    };
    push_be32(v, u32::from(len));
    v.extend((0..name).map(|_| b'a' + rng.below(26) as u8));
}

/// Ошибка VNC: длина причины (младший байт перекошен) и причина.
fn vnc_reason(rng: &mut TestRng, v: &mut Vec<u8>) {
    let n = rng.below(12);
    let hi = if rng.below(4) == 0 {
        rng.next() as u32 & 0xffff_ff00
    } else {
        0
    };
    push_be32(v, hi | u32::from(skewed(rng, n)));
    v.extend((0..n).map(|_| b'a' + rng.below(26) as u8));
}

/// VNC: префикс `RFB 003.003\n`, `003.007` или `003.008` (классификатор выбирает версию 3, 7 или 8), затем тип
/// безопасности 3.3 или список типов 3.7/3.8, результат 3.8, ошибка с причиной или ServerInit, иногда хвост.
fn vnc_stream(rng: &mut TestRng) -> Vec<u8> {
    let version = [3, 7, 8][rng.below(3)];
    let mut v = format!("RFB 003.00{version}\n").into_bytes();
    if version == 3 {
        let t = [0, 1, 2, rng.next() as u32][rng.below(4)];
        push_be32(&mut v, t);
        match t {
            0 => vnc_reason(rng, &mut v),
            1 => vnc_server_init(rng, &mut v),
            _ => {}
        }
    } else {
        let n = rng.below(4);
        v.push(n as u8);
        if n == 0 {
            vnc_reason(rng, &mut v);
        } else {
            v.extend((0..n).map(|_| [1, 2, 16, rng.next() as u8][rng.below(4)]));
            let ok = version == 7 || {
                let r = [0, 0, 1, rng.next() as u32][rng.below(4)];
                push_be32(&mut v, r);
                if r != 0 {
                    vnc_reason(rng, &mut v);
                }
                r == 0
            };
            if ok {
                vnc_server_init(rng, &mut v);
            }
        }
    }
    v.extend((0..rng.below(8)).map(|_| rng.next() as u8));
    v
}

/// RDP: 1-4 блока TPKT, в каждом COTP и CC (ответ согласования) с перекошенными длинами всех трёх уровней (длина
/// меньше заголовка, равная ему, на байт-три длиннее или короче содержимого), версия TPKT иногда не 3, тип PDU иногда
/// не CC, иногда содержимое обрезано; затем случайный хвост. Так достигаются обёртка счётчиков и пропускаемый байт.
fn rdp_stream(rng: &mut TestRng) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..1 + rng.below(4) {
        let mut cc = vec![
            [2, 3, 2, 1, rng.next() as u8][rng.below(5)],
            rng.next() as u8,
            0,
            0,
        ];
        cc.extend_from_slice(&[[0, 1, 2, 3, 5][rng.below(5)], 0, 0, 0]);
        cc[2] = if rng.below(8) == 0 {
            rng.below(4) as u8
        } else {
            skewed(rng, 8)
        };
        cc.truncate(cc.len() - rng.below(3));
        let mut cotp = vec![0, [0xd0, 0xd0, 0xd0, 0xe0, rng.next() as u8][rng.below(5)]];
        cotp.extend((0..5).map(|_| rng.next() as u8));
        cotp.extend_from_slice(&cc);
        cotp[0] = if rng.below(8) == 0 {
            rng.below(6) as u8
        } else {
            skewed(rng, 6 + cc.len())
        };
        let len = match rng.below(10) {
            0 => rng.below(4),
            1 => 4,
            _ => usize::from(skewed(rng, 4 + cotp.len())),
        };
        v.extend_from_slice(&[
            if rng.below(12) == 0 {
                rng.next() as u8
            } else {
                3
            },
            0,
        ]);
        v.extend_from_slice(&[rng.next() as u8, u8::try_from(len).unwrap_or(255)]);
        v.extend_from_slice(&cotp);
    }
    v.extend((0..rng.below(8)).map(|_| rng.next() as u8));
    v
}

/// I3 ревью задач 11-13: структурные потоки SSH, VNC и RDP проходят глубже первого байта. Каждый прогон
/// считает достигнутые состояния ([`Parser::probe`]) и требует их минимум; случайный вариант остаётся в
/// [`binary_parsers_never_panic`].
#[test]
fn structured_parsers_never_panic_and_reach_deep_states() {
    use std::collections::BTreeSet;
    let mut rng = TestRng(0x51_7e_c3_11);
    let mut ssh = BTreeSet::new();
    for _ in 0..3000 {
        let data = ssh_stream(&mut rng);
        probed(&mut rng, 22, None, &data, &mut ssh);
    }
    // Идентификация 0, длина 21-24, длина набивки 10, код 11, пропуск 20, ошибка 31, стоп 32.
    for state in [0, 10, 11, 20, 21, 22, 23, 24, 31, 32] {
        assert!(
            ssh.contains(&state),
            "SSH state {state} never reached: {ssh:?}"
        );
    }

    let mut vnc = BTreeSet::new();
    for _ in 0..3000 {
        let data = vnc_stream(&mut rng);
        probed(&mut rng, 5900, None, &data, &mut vnc);
    }
    // 3.3: тип 50-53; ошибка 60-64; 3.7/3.8: число типов 100, типы 101; результат 3.8 300-303; ServerInit 200-224;
    // DONE 400 и после него 401.
    for state in (50..=53)
        .chain(60..=64)
        .chain([100, 101])
        .chain(200..=224)
        .chain(300..=303)
        .chain([400, 401])
    {
        assert!(
            vnc.contains(&state),
            "VNC state {state} never reached: {vnc:?}"
        );
    }

    let mut rdp = BTreeSet::new();
    for _ in 0..6000 {
        let data = rdp_stream(&mut rng);
        probed(&mut rng, 3389, Some(app_id::RDP), &data, &mut rdp);
    }
    let field = |shift: u32| {
        rdp.iter()
            .map(|p| (p >> shift) & 0xf)
            .collect::<BTreeSet<_>>()
    };
    let flag = |bit: u32| rdp.iter().any(|p| p & (1 << bit) != 0);
    assert_eq!(field(0), (0..=5).collect(), "TPKT states");
    assert_eq!(field(4), (0..=8).collect(), "COTP states");
    assert_eq!(field(8), (0..=9).collect(), "CC states");
    assert!(flag(12), "TPKT counter never wrapped");
    assert!(flag(13), "COTP length never wrapped");
    assert!(flag(14), "no scope ever waited for the skipped byte");
    assert!(flag(15), "UNKNOWN never reached");
}

#[test]
fn deferred_heur_merges_reserved_prefix_and_logical_order() {
    use super::banout::Banout;
    use crate::tcp::app::ByteBudget;
    let mut b = Banout::default();
    let mut pending = Banout::default();
    let mut budget = ByteBudget::new(20);
    pending.append(&mut budget, app_id::HEUR, &[b'a'; 250]);
    b.commit_deferred_heur(&mut pending, &mut budget);
    assert_eq!(budget.left(), 0);
    assert_eq!(b.nodes(), [(0, 0), (app_id::HEUR, 250)]);
    budget.give(30);
    pending.append(&mut budget, app_id::HEUR, b"later");
    b.commit_deferred_heur(&mut pending, &mut budget);
    assert_eq!(budget.left(), 30);
    b.append(&mut budget, app_id::RDP, b"label");
    assert_eq!(
        b.flush(&mut budget),
        [
            (app_id::RDP, b"label".to_vec()),
            (app_id::HEUR, vec![b'a'; 20])
        ]
    );
    assert_eq!(budget.left(), 50);
    assert_eq!(pending.held(), 0);

    let mut b = Banout::default();
    let mut budget = ByteBudget::new(100);
    b.append(&mut budget, app_id::HEUR, b"ab");
    pending.append(&mut budget, app_id::HEUR, b"cd");
    b.commit_deferred_heur(&mut pending, &mut budget);
    assert_eq!(budget.left(), 96);
    assert_eq!(b.flush(&mut budget), [(app_id::HEUR, b"abcd".to_vec())]);
    assert_eq!(budget.left(), 100);
}

#[test]
fn rdp_zero_length_cotp_never_asserts() {
    let data = b"\x03\0\0\x0c\x06\xd0\0\0\0\0\0X";
    let got = forced(app_id::RDP, &[data]);
    assert_eq!(got.records, [(app_id::HEUR, data[4..].to_vec())]);
}

#[test]
fn rdp_releases_valid_and_incomplete_shadows() {
    use crate::tcp::app::{ByteBudget, Session};
    let cfg = session::BannerConfig::new(&TcpBannerSettings::default());
    let packet = b"\x03\0\0\x13\x0e\xd0\0\0\x12\x34\0\x02\0\x08\0\x02\0\0\0";
    for (data, held, want) in [
        (
            packet.as_slice(),
            33,
            vec![(app_id::RDP, b" NLA-supported".to_vec())],
        ),
        (&packet[..14], 27, vec![]),
    ] {
        let mut sess = cfg.forced(3389, app_id::RDP);
        let mut budget = ByteBudget::new(1000);
        let mut acts = vec![];
        sess.parse(data, &mut budget, &mut acts);
        assert_eq!(budget.left(), 1000 - held);
        assert_eq!(sess.flush(&mut budget), want);
        assert_eq!(budget.left(), 1000);
        assert!(sess.flush(&mut budget).is_empty());
        assert_eq!(budget.left(), 1000);
    }
    // Даже тень правильного потока ограничена общим бюджетом и учитывает отказы до её удаления.
    let mut sess = cfg.forced(3389, app_id::RDP);
    let mut budget = ByteBudget::new(20);
    sess.parse(packet, &mut budget, &mut vec![]);
    assert!(budget.dropped() > 0);
    assert!(sess.flush(&mut budget).is_empty());
    assert_eq!(budget.left(), 20);
}

#[test]
fn deferred_heur_source_loss_survives_repeated_merge() {
    use super::banout::Banout;
    use crate::tcp::app::ByteBudget;
    let mut b = Banout::default();
    let mut pending = Banout::default();
    let mut budget = ByteBudget::new(5);
    b.append(&mut budget, app_id::HEUR, b"ab");
    pending.append(&mut budget, app_id::HEUR, b"cdefgh");
    budget.give(10);
    b.commit_deferred_heur(&mut pending, &mut budget);
    pending.append(&mut budget, app_id::HEUR, b"later");
    b.commit_deferred_heur(&mut pending, &mut budget);
    assert_eq!(b.nodes(), [(app_id::HEUR, 13)]);
    assert_eq!(b.flush(&mut budget), [(app_id::HEUR, b"abcde".to_vec())]);
    assert_eq!(budget.left(), 15);
}

#[test]
fn telnet_reply_is_send_copy_at_the_session() {
    // Флаг TCP__copy виден только на уровне сессии: офлайн-драйвер сводит Send и SendCopy в одно действие.
    use crate::tcp::app::{ByteBudget, Session, SessionAction};
    let cfg = session::BannerConfig::new(&TcpBannerSettings::default());
    let mut sess = cfg.forced(23, app_id::TELNET);
    let mut budget = ByteBudget::new(1000);
    let mut acts = vec![];
    sess.parse(
        b"\xff\xfd\x20\xff\xfb\x01\xff\xfd\x01\xff\xfb\x20",
        &mut budget,
        &mut acts,
    );
    assert_eq!(
        acts,
        [SessionAction::SendCopy(
            b"\xff\xfc\x01\xff\xfe\x20".to_vec()
        )]
    );
}

#[test]
fn vnc_done_actions_do_not_depend_on_the_split() {
    // E2.9 на стороне Rust: после RFB_DONE ровно одно лишнее закрытие в любой нарезке, не по одному на сегмент.
    for data in [
        &b"RFB 003.008\n\0\0\0\x01\x03badTAIL"[..],
        b"RFB 003.003\n\0\0\0\x02tail",
    ] {
        let whole = banner_stream(&TcpBannerSettings::default(), 5900, None, &[data]);
        assert_eq!(
            whole
                .actions
                .iter()
                .filter(|a| **a == StreamAction::Close)
                .count(),
            2
        );
        for segs in [
            data.chunks(1).collect::<Vec<_>>(),
            data.chunks(3).collect(),
            data.chunks(7).collect(),
        ] {
            let got = banner_stream(&TcpBannerSettings::default(), 5900, None, &segs);
            assert_eq!(got.actions, whole.actions);
            assert_eq!(got.records, whole.records);
        }
    }
}

#[test]
fn deferred_heur_refunds_other_staged_records() {
    use super::banout::Banout;
    use crate::tcp::app::ByteBudget;
    let mut b = Banout::default();
    let mut pending = Banout::default();
    let mut budget = ByteBudget::new(100);
    pending.append(&mut budget, app_id::RDP, b"label");
    pending.append(&mut budget, app_id::HEUR, b"raw");
    assert_eq!(budget.left(), 92);
    b.commit_deferred_heur(&mut pending, &mut budget);
    // HEUR переехал без повторного списания, чужая запись возвращена в бюджет целиком.
    assert_eq!(budget.left(), 97);
    assert_eq!(b.flush(&mut budget), [(app_id::HEUR, b"raw".to_vec())]);
    assert_eq!(budget.left(), 100);
    assert_eq!(pending.held(), 0);
}

#[test]
fn ssh_high_bit_length_is_unsigned_and_does_not_resync() {
    // src/proto-banner1.h:240-242 stores size_t, not u32. Underflow is explicitly wrapping.
    for first in [0x7f, 0x80, 0xff] {
        let data = [
            b"SSH-2.0-x\n".as_slice(),
            &[first, 0, 0, 0, 0, 20],
            b"abcde\0\0\0\x08\x04\x14abcde",
        ]
        .concat();
        let got = forced(app_id::SSH2, &[&data]);
        assert_eq!(got.records, [(app_id::SSH2, data.clone())]);
        assert_eq!(got.actions.len(), 2);
        assert_eq!(
            got.actions[0],
            StreamAction::Send(b"SSH-2.0-OPENSSH_7.9\r\n".to_vec())
        );
    }
}
