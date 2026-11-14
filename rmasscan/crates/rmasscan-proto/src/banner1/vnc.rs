//! RFB/VNC: `src/proto-vnc.c:35-337`, masscan 8e6b3b0, AGPL-3.0. Выбор None даже без предложения,
//! младший байт длины ошибки и повторное закрытие DONE сохранены (D7, E3).
use super::session::{ParseCx, Parser};
use crate::app_id;

pub(super) struct Vnc {
    state: u16,
    version: u8,
    value: u32,
    count: u8,
}
impl Vnc {
    pub(super) fn new(version: u8) -> Self {
        Self {
            state: 0,
            version,
            value: 0,
            count: 0,
        }
    }
}
const DONE: u16 = 400;

fn sectype(cx: &mut ParseCx<'_>, value: u32) {
    let name = match value {
        0 => "invalid",
        1 => "none",
        2 => "VNC-chap",
        5 => "RA2",
        6 => "RA2ne",
        7 => "SSPI",
        8 => "SSPIne",
        16 => "Tight",
        17 => "Ultra",
        18 => "TLS",
        19 => "VeNCrypt",
        20 => "GTK-VNC-SASL",
        21 => "MD5",
        22 => "Colin-Dean-xvp",
        30 => "Apple30",
        35 => "Apple35",
        _ => "",
    };
    cx.append(
        app_id::VNC_INFO,
        format!(
            "  {}",
            if name.is_empty() {
                value.to_string()
            } else {
                name.to_owned()
            }
        )
        .as_bytes(),
    );
}
impl Parser for Vnc {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        for &c in px {
            match self.state {
                0..=10 => {
                    cx.append(app_id::VNC_RFB, &[c]);
                    self.state += 1;
                }
                11 => {
                    cx.append(app_id::VNC_RFB, &[c]);
                    if c == b'\n' {
                        let version = self.version % 10;
                        cx.send(match version {
                            7 => b"RFB 003.007\n",
                            8..=9 => b"RFB 003.008\n",
                            _ => b"RFB 003.003\n",
                        });
                        self.state = if version < 7 { 50 } else { 100 };
                    } else {
                        self.state = 401;
                        cx.close();
                    }
                }
                50 | 60 | 300 | 220 => {
                    self.value = u32::from(c);
                    self.state += 1;
                }
                51..=52 | 61..=62 | 301..=302 | 221..=222 => {
                    self.value = (self.value << 8) | u32::from(c);
                    self.state += 1;
                }
                53 => {
                    self.value = (self.value << 8) | u32::from(c);
                    cx.append(app_id::VNC_INFO, b"Security types:\n");
                    sectype(cx, self.value);
                    match self.value {
                        0 => self.state = 60,
                        1 => {
                            cx.send(&[1]);
                            self.state = 200;
                        }
                        _ => {
                            self.state = DONE;
                            cx.close();
                        }
                    }
                }
                303 => {
                    self.value = (self.value << 8) | u32::from(c);
                    if self.value == 0 {
                        cx.send(&[1]);
                        self.state = 200;
                    } else {
                        self.state = 60;
                    }
                }
                // `src/proto-vnc.c:214-228`: assignment, not OR; close on the byte after the reason.
                63 => {
                    self.value = u32::from(c);
                    cx.append(app_id::VNC_INFO, b"ERROR: ");
                    self.state = 64;
                }
                64 => {
                    if self.value == 0 {
                        self.state = DONE;
                        cx.close();
                    } else {
                        self.value -= 1;
                        cx.append(app_id::VNC_INFO, &[c]);
                    }
                }
                100 => {
                    self.count = c;
                    if c == 0 {
                        self.state = 60;
                    } else {
                        self.state = 101;
                        cx.append(app_id::VNC_INFO, b"Security types:\n");
                    }
                }
                101 => {
                    self.count = self.count.saturating_sub(1);
                    sectype(cx, u32::from(c));
                    cx.append(app_id::VNC_INFO, b"\n");
                    if self.count == 0 {
                        match self.version {
                            0..=6 => {
                                self.state = 200;
                                cx.send(&[1]);
                            }
                            7 => {
                                self.state = 200;
                                cx.send(&[1, 1]);
                            }
                            _ => {
                                self.state = 300;
                                cx.send(&[1]);
                            }
                        }
                    }
                }
                200 | 202 => {
                    self.value = u32::from(c);
                    self.state += 1;
                }
                201 | 203 => {
                    self.value = (self.value << 8) | u32::from(c);
                    cx.append(
                        app_id::VNC_RFB,
                        format!(
                            " {}={}",
                            if self.state == 201 { "width" } else { "height" },
                            self.value
                        )
                        .as_bytes(),
                    );
                    self.state += 1;
                }
                204..=219 => self.state += 1,
                223 => {
                    self.value = (self.value << 8) | u32::from(c);
                    if self.value == 0 {
                        self.state = DONE;
                        cx.close();
                    } else {
                        cx.append(app_id::VNC_INFO, b"Name: ");
                        self.state = 224;
                    }
                }
                224 => {
                    self.value = self.value.saturating_sub(1);
                    cx.append(app_id::VNC_INFO, &[c]);
                    if self.value == 0 {
                        cx.append(app_id::VNC_INFO, b"\n");
                        self.state = DONE;
                        cx.close();
                    }
                }
                DONE => {
                    cx.close();
                    self.state = 401;
                    break;
                }
                _ => break,
            }
        }
    }
}
