//! Независимые поведенческие проверки D10-D11 (memcached по TCP и Minecraft); golden-тесты сравнивают все
//! байты с C.
use super::*;
use crate::app_id;

fn forced(app: u16, segments: &[&[u8]]) -> StreamResult {
    banner_stream(&TcpBannerSettings::default(), 9999, Some(app), segments)
}

#[test]
fn memcached_tcp_never_closes() {
    // `socket` в `memcached_tcp_parse` не используется (`src/proto-memcached.c:118`): ни закрытий, ни отправок.
    let mut rng = TestRng(0x1214732026);
    let mut streams: Vec<Vec<u8>> = [
        &b"STAT pid 1\r\nSTAT uptime 5\r\nEND\r\n"[..],
        b"ERROR\r\nSTAT\nHELLO",
        b"end",
        b"",
    ]
    .iter()
    .map(|s| s.to_vec())
    .collect();
    for _ in 0..200 {
        streams.push((0..128).map(|_| rng.next() as u8).collect());
    }
    for data in &streams {
        for segs in [vec![data.as_slice()], data.chunks(1).collect()] {
            let got = forced(app_id::MEMCACHED, &segs);
            assert!(got.actions.is_empty(), "{data:?}");
        }
    }
}

#[test]
fn minecraft_record_is_raw_stream_when_balanced() {
    // E2.7: запись это весь поток сырым, фавикон не вырезается (на неразрезанном потоке C дописывает сегмент
    // как есть, `src/proto-mc.c:66-67`), и так в любой нарезке.
    let data = b"{\"description\":{\"text\":\"lab\"},\"favicon\":\"data:image/png;base64,AAAA\"}";
    for segs in [
        vec![data.as_slice()],
        data.chunks(1).collect(),
        data.chunks(5).collect(),
    ] {
        let got = forced(app_id::MC, &segs);
        assert_eq!(got.records, [(app_id::MC, data.to_vec())]);
    }
    let got = forced(app_id::MC, &[data]);
    assert_eq!(got.actions, [StreamAction::Close]);
}

#[test]
fn minecraft_unbalanced_gives_no_record() {
    // Счётчик на сбросе `> 0` (открытые скобки не закрыты): записи нет, даже если по пути он опускался до нуля.
    for data in [&b"{\"a\":{"[..], b"{}{", b"{\"a\":1"] {
        for segs in [vec![data], data.chunks(1).collect()] {
            let got = forced(app_id::MC, &segs);
            assert!(got.records.is_empty(), "{data:?}");
        }
    }
}

#[test]
fn minecraft_closes_when_count_drops() {
    // Проверка C в конце каждого вызова (`src/proto-mc.c:64-65`): целиком одно закрытие, по сегментам на
    // каждом сегменте со счётчиком `<= 0` на его конце.
    let got = forced(app_id::MC, &[b"{}x"]);
    assert_eq!(got.actions, [StreamAction::Close]);
    let got = forced(app_id::MC, &[b"{", b"}", b"}"]);
    assert_eq!(got.actions, [StreamAction::Close, StreamAction::Close]);
    assert_eq!(got.records, [(app_id::MC, b"{}}".to_vec())]);
    let got = forced(app_id::MC, &[b"{", b"{"]);
    assert!(got.actions.is_empty());
}

#[test]
fn minecraft_hijacks_json_on_any_port() {
    // Безъякорный `{"` (`src/proto-banner1.c` шаблоны): поток на HTTP-порту классифицируется как Minecraft, и
    // парсер видит весь поток с начала, включая байты до совпадения.
    let data = b"prefix {\"a\":1}";
    let got = banner_stream(&TcpBannerSettings::default(), 80, None, &[data]);
    assert_eq!(got.app_proto, Some(app_id::MC));
    assert_eq!(got.records, [(app_id::MC, data.to_vec())]);
    assert_eq!(got.actions, [StreamAction::Close]);
}

#[test]
fn minecraft_flush_releases_staged_budget() {
    use crate::tcp::app::{ByteBudget, Session};
    let cfg = session::BannerConfig::new(&TcpBannerSettings::default());
    for (data, want) in [
        (&b"{\"a\":1}"[..], vec![(app_id::MC, b"{\"a\":1}".to_vec())]),
        (b"{\"a\":{", vec![]),
    ] {
        let mut sess = cfg.forced(25565, app_id::MC);
        let mut budget = ByteBudget::new(1000);
        sess.parse(data, &mut budget, &mut vec![]);
        assert_eq!(budget.left(), 1000 - data.len());
        assert_eq!(sess.flush(&mut budget), want);
        assert_eq!(budget.left(), 1000);
        assert!(sess.flush(&mut budget).is_empty());
        assert_eq!(budget.left(), 1000);
    }
}

#[test]
fn memcached_minecraft_never_panic() {
    let mut rng = TestRng(0x005e_ed12);
    for app in [app_id::MEMCACHED, app_id::MC] {
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
    // Глубокие состояния Minecraft: длинные серии скобок в обе стороны.
    for data in [vec![b'{'; 5000], vec![b'}'; 5000]] {
        let got = forced(app_id::MC, &[&data]);
        assert!(got.records.iter().all(|r| r.1.len() <= 65_536));
    }
}
