//! Офлайн-драйвер каркаса (как [`crate::handle_udp`] подэтапа 4a): одна сессия порта, сегменты сервера по очереди,
//! затем сброс без бюджета. Для эталонов `tests/tcp_golden.rs` и фаззера `rmasscan-lab fuzz tcp`.

use crate::tcp::app::{ByteBudget, Session, SessionAction};

use super::hello::TcpBannerSettings;
use super::session::BannerConfig;

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
