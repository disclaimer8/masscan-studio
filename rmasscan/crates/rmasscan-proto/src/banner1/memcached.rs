//! Парсер баннера memcached по TCP: `memcached_tcp_parse` (`src/proto-memcached.c:106-223`) masscan
//! © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0; справка D10, E1.4, E2.6.
//!
//! Автомат общий с UDP ([`crate::memcached_text::MemcachedText`]): тот же разбор строк `STAT`, но состояние
//! живёт между сегментами соединения, а не создаётся на датаграмму. Закрытий и отправок у C здесь нет совсем
//! (`socket` помечен `UNUSEDPARM`, `:118`): парсер только дописывает `uptime=`, `time=` и `version=`.

use crate::app::app_id;
use crate::memcached_text::MemcachedText;

use super::session::{ParseCx, Parser};

/// `pstate->sub.memcached` плюс номер состояния, всё внутри [`MemcachedText`].
pub(crate) struct Memcached {
    text: MemcachedText,
}

impl Default for Memcached {
    fn default() -> Self {
        Memcached {
            text: MemcachedText::new(),
        }
    }
}

impl Parser for Memcached {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut out = Vec::new();
        self.text.parse(px, &mut out);
        if !out.is_empty() {
            cx.append(app_id::MEMCACHED, &out);
        }
    }
}
