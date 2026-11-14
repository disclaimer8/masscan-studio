//! RDP: `src/proto-tcp-rdp.c:19-289`, masscan 8e6b3b0, AGPL-3.0. Вложенные циклы C
//! выполняются как ограниченные области: ранний выход возвращает length+1, счётчики оборачиваются, лишний байт
//! пропускается. Границы областей задаёт протокол, а не сегмент TCP (правило неразрезанного потока E2.5).
use super::banout::Banout;
use super::session::{ParseCx, Parser};
use crate::app_id;

#[derive(Default)]
pub(super) struct Rdp {
    state: u8,
    left: u16,
    history: Banout,
    history_sent: bool,
    cotp_state: u8,
    cotp_len: u8,
    cotp_type: u8,
    cotp: Option<Scope>,
    cc_state: u8,
    cc_len: u8,
    cc_type: u8,
    result: u32,
    cc: Option<Scope>,
}

/// Не больше двух активных областей (COTP <=65535, CC <=255); их байты и история <=65536 оплачены общим бюджетом.
struct Scope {
    limit: u32,
    seen: u32,
    skip: bool,
    raw: bool,
    held: Banout,
}
impl Scope {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            seen: 0,
            skip: false,
            raw: false,
            held: Banout::default(),
        }
    }
    fn observe(&mut self, cx: &mut ParseCx<'_>, c: u8) {
        if self.seen < self.limit {
            if self.raw {
                cx.append(app_id::HEUR, &[c]);
            } else if !self.skip {
                self.held.append(cx.budget, app_id::HEUR, &[c]);
            }
        }
        self.seen += 1;
    }
    fn done(&self) -> bool {
        self.seen >= self.limit + u32::from(self.skip)
    }
    fn raw(&mut self, cx: &mut ParseCx<'_>) {
        self.raw = true;
        self.skip = true;
        cx.banout.commit_deferred_heur(&mut self.held, cx.budget);
    }
    fn discard(&mut self, cx: &mut ParseCx<'_>) {
        drop(self.held.flush(cx.budget));
    }
}

impl Rdp {
    fn unknown(&mut self, cx: &mut ParseCx<'_>) {
        cx.banout.commit_deferred_heur(&mut self.history, cx.budget);
        self.history_sent = true;
    }
    fn end_cotp(&mut self, cx: &mut ParseCx<'_>) {
        if let Some(mut scope) = self.cotp.take() {
            self.left = self.left.wrapping_sub(scope.seen as u16);
            self.state = if self.left == 0 { 0 } else { 4 };
            scope.discard(cx);
        }
    }
    fn content(&mut self, cx: &mut ParseCx<'_>, c: u8) {
        let mut scope = self
            .cotp
            .take()
            .unwrap_or_else(|| Scope::new(u32::from(self.left)));
        scope.observe(cx, c);
        if scope.skip {
            // UNKNOWN и неизвестный PDU: C выходит на length+1 (`:187-190`, `:181-183`).
        } else {
            match self.cotp_state {
                0 => {
                    self.cotp_len = c;
                    if c < 6 {
                        self.cotp_state = 8;
                    } else {
                        self.cotp_len -= 6;
                        self.cotp_state = 1;
                    }
                }
                1 => {
                    self.cotp_type = c;
                    self.cotp_state = 2;
                }
                2..=5 => self.cotp_state += 1,
                6 => {
                    self.cc_state = 0;
                    self.cotp_state = 7;
                }
                7 if self.cotp_type != 0xd0 => {
                    cx.append(app_id::RDP, b" COTPPDU=unknown");
                    scope.skip = true;
                    scope.discard(cx);
                }
                7 => {
                    // C зовёт cc_parse(...,0) и assert падает (`src/proto-tcp-rdp.c:158-169`).
                    // Тотальный отказ: вся текущая COTP-область в HEUR, как соседняя UNKNOWN-ветка.
                    if self.cotp_len == 0 {
                        self.cotp_state = 8;
                        scope.raw(cx);
                    } else {
                        self.cc_byte(cx, c, &mut scope);
                    }
                }
                _ => scope.raw(cx),
            }
        }
        let done = scope.done() && self.cc.is_none();
        self.cotp = Some(scope);
        if done {
            self.end_cotp(cx);
        }
    }
    fn cc_byte(&mut self, cx: &mut ParseCx<'_>, c: u8, cotp: &mut Scope) {
        // Текущий байт уже учтён cotp.observe, но входит в предел новой CC-области.
        let mut cc = self.cc.take().unwrap_or_else(|| {
            Scope::new(u32::from(self.cotp_len).min(cotp.limit.saturating_sub(cotp.seen - 1)))
        });
        cc.observe(cx, c);
        if !cc.skip {
            match self.cc_state {
                0 => {
                    self.cc_type = c;
                    self.cc_state = 1;
                }
                1 => self.cc_state = 2,
                2 => {
                    self.cc_len = c;
                    if c < 4 {
                        self.cc_state = 9;
                    } else {
                        self.cc_len -= 4;
                        self.cc_state = 3;
                    }
                }
                3 => {
                    if matches!(self.cc_type, 2 | 3) {
                        self.result = 0;
                        self.cc_state = 4;
                    } else {
                        self.cc_state = 8;
                    }
                }
                4..=7 => {
                    if self.cc_len == 0 {
                        self.cc_state = 8;
                    } else {
                        self.cc_len -= 1;
                        self.result = (self.result >> 8) | (u32::from(c) << 24);
                        self.cc_state += 1;
                        if self.cc_state == 8 {
                            cx.append(
                                app_id::RDP,
                                match (self.cc_type, self.result) {
                                    (2, n) if n & 2 != 0 => b" NLA-supported",
                                    (2, _) => b" NLA-unused",
                                    (3, 5) => b" NLA-unsupported",
                                    _ => b" failure",
                                },
                            );
                        }
                    }
                }
                8 => {
                    cc.skip = true;
                    cc.discard(cx);
                }
                _ => cc.raw(cx),
            }
        }
        if cc.done() {
            self.cotp_len = self.cotp_len.wrapping_sub(cc.seen as u8);
            self.cotp_state = if self.cotp_len == 0 { 8 } else { 7 };
            cc.discard(cx);
        } else {
            self.cc = Some(cc);
        }
    }
}
impl Parser for Rdp {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        for &c in px {
            if self.history_sent {
                cx.append(app_id::HEUR, &[c]);
                continue;
            }
            self.history.append(cx.budget, app_id::HEUR, &[c]);
            match self.state {
                0 => {
                    if c != 3 {
                        self.state = 5;
                        self.unknown(cx);
                    } else {
                        self.left = 0;
                        self.cotp_state = 0;
                        self.state = 1;
                    }
                }
                1..=2 => self.state += 1, // high length byte is intentionally ignored (`:239-242`).
                3 => {
                    self.left = u16::from(c);
                    self.state = match c {
                        0..=3 => 5,
                        4 => 0,
                        _ => {
                            self.left -= 4;
                            4
                        }
                    };
                }
                4 => self.content(cx, c),
                _ => self.unknown(cx),
            }
        }
    }
    fn flush(&mut self, cx: &mut ParseCx<'_>) {
        // Неактивированные тени не являются баннерами; все резервации возвращаются ровно один раз.
        drop(self.history.flush(cx.budget));
        if let Some(mut scope) = self.cotp.take() {
            scope.discard(cx);
        }
        if let Some(mut scope) = self.cc.take() {
            scope.discard(cx);
        }
    }
}
