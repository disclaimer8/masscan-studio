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
