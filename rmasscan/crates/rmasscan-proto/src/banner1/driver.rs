//! Офлайн-драйвер каркаса (как [`crate::handle_udp`] подэтапа 4a): одна сессия порта, сегменты сервера по очереди,
//! затем сброс без бюджета. Для эталонов `tests/tcp_golden.rs` и фаззера `rmasscan-lab fuzz tcp`.

use crate::tcp::app::{ByteBudget, Session, SessionAction};

use super::banout::{Banout, Base64Stream};
use super::hello::TcpBannerSettings;
use super::session::{BannerConfig, ParseCx, Parser};
use super::tls::{Tls, TlsFlags};
use super::x509::X509;

/// Действие разбора: `tcpapi_send` (байты) или `tcpapi_close`, в порядке вызова.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamAction {
    Send(Vec<u8>),
    Close,
}

/// Итог потока: номер приложения, который выбрал классификатор (`tcb_state->app_proto` C после всех вызовов;
/// `None` это PROTO_NONE), записи `banner_flush` в порядке C и действия разбора.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamResult {
    pub app_proto: Option<u16>,
    pub records: Vec<(u16, Vec<u8>)>,
    pub actions: Vec<StreamAction>,
}

/// Поток сервера `segments` на порт `port` через сессию баннера: `force_app` запускает парсер приложения с этим
/// номером без классификатора (семейство фаззера). Бюджет не ограничен; предел записи 65 536 байт (Р5) действует.
#[doc(hidden)]
pub fn banner_stream(
    s: &TcpBannerSettings,
    port: u16,
    force_app: Option<u16>,
    segments: &[&[u8]],
) -> StreamResult {
    let cfg = BannerConfig::new(s);
    let mut session = match force_app {
        Some(app) => cfg.forced(port, app),
        None => cfg.session(port),
    };
    let mut budget = ByteBudget::new(usize::MAX);
    let mut acts = Vec::new();
    for seg in segments {
        session.parse(seg, &mut budget, &mut acts);
    }
    let app_proto = session.app_proto();
    let records = session.flush(&mut budget);
    StreamResult {
        app_proto,
        records,
        actions: acts
            .into_iter()
            .map(|a| match a {
                SessionAction::Send(b) | SessionAction::SendCopy(b) => StreamAction::Send(b),
                SessionAction::SendShared(b) => StreamAction::Send(b.to_vec()),
                SessionAction::Close => StreamAction::Close,
            })
            .collect(),
    }
}

/// Один сертификат DER сегментами `segments` через разбор X.509 (задача 3 подэтапа 4c): `count` как ставит
/// `parse_server_cert` (1 — лист, 2 и дальше — цепочка), бюджет не ограничен, предел записи 65 536 (Р5)
/// действует. Возвращает записи сброса в порядке C. Для эталонов `tests/x509_golden.rs` и фаззера `x509`.
#[doc(hidden)]
pub fn x509_stream(count: u32, segments: &[&[u8]]) -> Vec<(u16, Vec<u8>)> {
    let total: usize = segments.iter().map(|s| s.len()).sum();
    let mut x = X509::default();
    x.init(total, count);
    let mut banout = Banout::default();
    let mut budget = ByteBudget::new(usize::MAX);
    let mut base64 = Base64Stream::default();
    let mut acts = Vec::new();
    for seg in segments {
        let mut cx = ParseCx {
            banout: &mut banout,
            budget: &mut budget,
            acts: &mut acts,
            base64: &mut base64,
            capture_html: false,
            tls_flags: TlsFlags::default(),
            starttls: false,
        };
        x.feed(&mut cx, seg);
    }
    banout.flush(&mut budget)
}

/// Один поток TLS сегментами `segments` через парсер записей (задача 4 подэтапа 4c) с флагами захвата и
/// режимов (`src/proto-banner1.h:31-38`): записи сброса и действия в порядке C. Для эталонов
/// `tests/tls_golden.rs` и семейства фаззера `tls`.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn tls_stream(
    capture_cert: bool,
    capture_heartbleed: bool,
    capture_ticketbleed: bool,
    heartbleed: bool,
    ticketbleed: bool,
    poodle_sslv3: bool,
    segments: &[&[u8]],
) -> StreamResult {
    let flags = TlsFlags {
        capture_cert,
        capture_heartbleed,
        capture_ticketbleed,
        heartbleed,
        ticketbleed,
        poodle_sslv3,
    };
    let mut parser = Tls::default();
    let mut banout = Banout::default();
    let mut budget = ByteBudget::new(usize::MAX);
    let mut base64 = Base64Stream::default();
    let mut acts = Vec::new();
    for seg in segments {
        let mut cx = ParseCx {
            banout: &mut banout,
            budget: &mut budget,
            acts: &mut acts,
            base64: &mut base64,
            capture_html: false,
            tls_flags: flags,
            starttls: false,
        };
        parser.parse(&mut cx, seg);
    }
    StreamResult {
        app_proto: Some(crate::app::app_id::SSL3),
        records: banout.flush(&mut budget),
        actions: acts
            .into_iter()
            .map(|a| match a {
                SessionAction::Send(b) | SessionAction::SendCopy(b) => StreamAction::Send(b),
                SessionAction::SendShared(b) => StreamAction::Send(b.to_vec()),
                SessionAction::Close => StreamAction::Close,
            })
            .collect(),
    }
}
