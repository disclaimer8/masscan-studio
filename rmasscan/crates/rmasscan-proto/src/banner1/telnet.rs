//! Telnet: `src/proto-tcp-telnet.c:93-252`, masscan 8e6b3b0, AGPL-3.0. Отказы TCP__copy по каждому
//! вызову, в порядке опций; INVALID сохраняет один следующий байт (E2.4).
use super::session::{ParseCx, Parser};
use crate::app_id;

#[derive(Default)]
pub(super) struct Telnet {
    state: u8,
}

impl Parser for Telnet {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut nego = [0u8; 256];
        for &c in px {
            if self.state == 9 {
                break;
            }
            cx.append(app_id::TELNET, &[c]);
            self.state = match self.state {
                0 => {
                    if c == 255 {
                        1
                    } else {
                        0
                    }
                }
                1 => match c {
                    240..=249 => 0,
                    250 => 6,
                    251 => 4,
                    252 => 5,
                    253 => 2,
                    254 => 3,
                    _ => 8,
                },
                2..=5 => {
                    nego[usize::from(c)] = if self.state < 4 { 252 } else { 254 };
                    0
                }
                6 => 7,
                7 => {
                    if c == 255 {
                        1
                    } else {
                        7
                    }
                }
                _ => 9,
            };
        }
        let mut reply = Vec::new();
        for (option, &cmd) in nego.iter().enumerate() {
            if cmd != 0 {
                reply.extend_from_slice(&[255, cmd, option as u8]);
            }
        }
        if !reply.is_empty() {
            cx.send_copy(&reply);
        }
    }
}
