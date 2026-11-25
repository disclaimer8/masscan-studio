//! Потоковый разбор SPNEGO ASN.1/DER (`spnego_decode` в `src/proto-x509.c:1062-1390`, подэтап 4d):
//! извлекает `responseToken` из `NegTokenResp` и передаёт его в [`super::ntlmssp::Ntlmssp`].
//!
//! Безопасная и независимая от нарезки (Р2, Р13) реализация:
//! - Явный стек кадров глубины `MAX_DEPTH = 9` (как `remainings[9]` в C).
//! - Сохраняет состояние между вызовами `feed` (исправляет C-баг в `proto-x509.c:1368`, где `x->state`
//!   не сохранялся и сегментированный SPNEGO сбрасывался).
//! - В `responseToken` корректно продвигает курсор и уменьшает остаток кадра, не перечитывая тело
//!   `responseToken` как ASN.1 и без двойного освобождения буфера NTLMSSP.

use super::ntlmssp::Ntlmssp;
use super::session::ParseCx;

/// Глубина стека ASN.1 (как `remainings[9]` в `src/proto-x509.h:20-24`).
const MAX_DEPTH: usize = 9;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    NegotiationTokenTag,
    Len,
    LenLen,
    NegTokenInitTag,
    NegTokenInitChoice,
    NegTokenRespTag,
    NegTokenRespChoice,
    MechTypeTag,
    NegStateTag,
    SupportedMechTag,
    ResponseTokenTag,
    MechListMicTag,
    MechTypesTag,
    ReqFlagsTag,
    MechTokenTag,
    MechTokenContent,
    ResponseTokenContent,
    ResponseTokenContent2,
    UnknownContents,
    Done,
}

#[derive(Clone, Copy, Debug, Default)]
struct Frame {
    brother: State,
    remaining: u16,
}

/// Потоковый парсер SPNEGO-блоба (GSS-API / NegTokenInit / NegTokenResp).
#[derive(Debug, Default)]
pub(crate) struct Spnego {
    stack: [Frame; MAX_DEPTH],
    depth: usize,
    state: State,
    brother_state: State,
    child_state: State,
    len_remaining: u16,
    len_of_len: u8,
    ntlmssp: Ntlmssp,
}

impl Spnego {
    /// `spnego_decode_init`: инициализирует внешний кадр длиной `length`.
    pub(crate) fn init(&mut self, length: usize) {
        self.depth = 0;
        self.state = State::NegotiationTokenTag;
        self.brother_state = State::UnknownContents;
        self.child_state = State::UnknownContents;
        self.len_remaining = 0;
        self.len_of_len = 0;
        self.ntlmssp.clear();
        if let Ok(len16) = u16::try_from(length) {
            self.stack[0] = Frame {
                brother: State::Done,
                remaining: len16,
            };
            self.depth = 1;
        }
    }

    /// Очищает внутренний буфер NTLMSSP при начале нового NBT-кадра.
    pub(crate) fn clear_ntlmssp(&mut self) {
        self.ntlmssp.clear();
    }

    /// `ASN1_push` (как в `x509.rs`): проверяет переполнение стека и остаток родителя.
    fn push(&mut self, brother: State, len: u16) {
        if self.depth == 0 || self.depth >= MAX_DEPTH {
            return;
        }
        let parent_rem = self.stack[self.depth - 1].remaining;
        if len > parent_rem {
            return;
        }
        self.stack[self.depth - 1].remaining = parent_rem - len;
        self.stack[self.depth] = Frame {
            brother,
            remaining: len,
        };
        self.depth += 1;
    }

    /// Подаёт очередной фрагмент SPNEGO-блоба.
    pub(crate) fn feed(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut i = 0;
        while i < px.len() {
            // Снимаем завершённые кадры перед каждым байтом (как `proto-x509.c:1116-1120`).
            while self.depth > 0 && self.stack[self.depth - 1].remaining == 0 {
                let brother = self.stack[self.depth - 1].brother;
                self.depth -= 1;
                if self.depth == 0 {
                    self.state = State::Done;
                    return;
                }
                self.state = brother;
            }
            if self.depth == 0 {
                return;
            }

            // Быстрый путь для тела responseToken: потребляем сразу весь доступный кусок.
            if matches!(
                self.state,
                State::ResponseTokenContent | State::ResponseTokenContent2
            ) {
                let rem = usize::from(self.stack[self.depth - 1].remaining);
                if self.state == State::ResponseTokenContent {
                    self.ntlmssp.init(rem);
                    self.state = State::ResponseTokenContent2;
                }
                let take = (px.len() - i).min(rem);
                self.ntlmssp.feed(cx, &px[i..i + take]);
                self.stack[self.depth - 1].remaining -= take as u16;
                i += take;
                if self.stack[self.depth - 1].remaining == 0 {
                    self.ntlmssp.clear();
                }
                continue;
            }

            let byte = px[i];
            i += 1;
            self.stack[self.depth - 1].remaining -= 1;

            match self.state {
                State::NegotiationTokenTag => {
                    self.brother_state = State::UnknownContents;
                    self.child_state = match byte {
                        0xa0 => State::NegTokenInitTag,
                        0xa1 => State::NegTokenRespTag,
                        0x60 => State::MechTypeTag,
                        _ => State::UnknownContents,
                    };
                    self.state = State::Len;
                }
                State::NegTokenRespChoice => {
                    self.brother_state = State::NegTokenRespChoice;
                    self.child_state = match byte {
                        0xa0 => State::NegStateTag,
                        0xa1 => State::SupportedMechTag,
                        0xa2 => State::ResponseTokenTag,
                        0xa3 => State::MechListMicTag,
                        _ => State::UnknownContents,
                    };
                    self.state = State::Len;
                }
                State::NegTokenRespTag => {
                    self.brother_state = State::UnknownContents;
                    self.child_state = if byte == 0x30 {
                        State::NegTokenRespChoice
                    } else {
                        State::UnknownContents
                    };
                    self.state = State::Len;
                }
                State::NegTokenInitChoice => {
                    self.brother_state = State::NegTokenInitChoice;
                    self.child_state = match byte {
                        0xa0 => State::MechTypesTag,
                        0xa1 => State::ReqFlagsTag,
                        0xa2 => State::MechTokenTag,
                        0xa3 => State::MechListMicTag,
                        _ => State::UnknownContents,
                    };
                    self.state = State::Len;
                }
                State::NegTokenInitTag => {
                    self.brother_state = State::UnknownContents;
                    self.child_state = if byte == 0x30 {
                        State::NegTokenInitChoice
                    } else {
                        State::UnknownContents
                    };
                    self.state = State::Len;
                }
                State::MechTypeTag => {
                    self.brother_state = State::NegotiationTokenTag;
                    self.child_state = State::UnknownContents;
                    self.state = State::Len;
                }
                State::NegStateTag
                | State::SupportedMechTag
                | State::MechListMicTag
                | State::MechTypesTag
                | State::ReqFlagsTag => {
                    self.brother_state = State::UnknownContents;
                    self.child_state = State::UnknownContents;
                    self.state = State::Len;
                }
                State::ResponseTokenTag => {
                    self.brother_state = State::UnknownContents;
                    self.child_state = State::ResponseTokenContent;
                    self.state = State::Len;
                }
                State::MechTokenTag => {
                    self.brother_state = State::UnknownContents;
                    self.child_state = State::MechTokenContent;
                    self.state = State::Len;
                }
                State::Len => {
                    if byte & 0x80 != 0 {
                        self.len_of_len = byte & 0x7f;
                        self.len_remaining = 0;
                        if self.len_of_len == 0 {
                            // Indefinite length (0x80): push 0-length frame to avoid infinite wait.
                            self.push(self.brother_state, 0);
                            self.state = self.child_state;
                        } else {
                            self.state = State::LenLen;
                        }
                    } else {
                        self.push(self.brother_state, u16::from(byte));
                        self.state = self.child_state;
                    }
                }
                State::LenLen => {
                    self.len_remaining = self.len_remaining.wrapping_shl(8) | u16::from(byte);
                    self.len_of_len = self.len_of_len.saturating_sub(1);
                    if self.len_of_len == 0 {
                        self.push(self.brother_state, self.len_remaining);
                        self.state = self.child_state;
                    }
                }
                State::MechTokenContent
                | State::UnknownContents
                | State::Done
                | State::ResponseTokenContent
                | State::ResponseTokenContent2 => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app_id;
    use crate::banner1::banout::{Banout, Base64Stream};
    use crate::banner1::tls::TlsFlags;
    use crate::tcp::app::ByteBudget;
    use std::sync::Arc;

    fn run_spnego(segs: &[&[u8]]) -> Vec<(u16, Vec<u8>)> {
        let total: usize = segs.iter().map(|s| s.len()).sum();
        let mut s = Spnego::default();
        s.init(total);
        let mut banout = Banout::default();
        let mut budget = ByteBudget::new(usize::MAX);
        let mut base64 = Base64Stream::default();
        let mut acts = Vec::new();
        for seg in segs {
            let mut cx = ParseCx {
                banout: &mut banout,
                budget: &mut budget,
                acts: &mut acts,
                base64: &mut base64,
                capture_html: false,
                tls_flags: TlsFlags::default(),
                starttls_hello: Arc::from(&[][..]),
                starttls: false,
                starttls_rest: Vec::new(),
            };
            s.feed(&mut cx, seg);
        }
        banout.flush(&mut budget)
    }

    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else if body.len() < 256 {
            out.push(0x81);
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.push((body.len() >> 8) as u8);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    }

    /// NegTokenResp с responseToken (NTLMSSP Type-2): результат одинаков целиком и побайтово (Р13).
    #[test]
    fn neg_token_resp_extracts_ntlmssp_in_all_splits() {
        let mut ntlm = vec![0u8; 56];
        ntlm[0..8].copy_from_slice(b"NTLMSSP\0");
        ntlm[8..12].copy_from_slice(&2u32.to_le_bytes());
        ntlm[48] = 10;
        ntlm[49] = 0;
        ntlm[50..52].copy_from_slice(&20348u16.to_le_bytes());
        ntlm[55] = 15;

        let neg_state = der_tlv(0xa0, &der_tlv(0x0a, &[0x01]));
        let supp_mech = der_tlv(
            0xa1,
            &der_tlv(
                0x06,
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a],
            ),
        );
        let resp_tok = der_tlv(0xa2, &der_tlv(0x04, &ntlm));
        let mut seq_body = Vec::new();
        seq_body.extend_from_slice(&neg_state);
        seq_body.extend_from_slice(&supp_mech);
        seq_body.extend_from_slice(&resp_tok);
        let blob = der_tlv(0xa1, &der_tlv(0x30, &seq_body));

        let whole = run_spnego(&[&blob]);
        assert_eq!(
            whole,
            [(app_id::SMB, b" version=10.0.20348 ntlm-ver=15".to_vec())]
        );
        let bytewise: Vec<&[u8]> = blob.chunks(1).collect();
        assert_eq!(run_spnego(&bytewise), whole);
    }
}
