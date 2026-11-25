//! Разбор NTLMSSP Type-2 Challenge (`src/proto-ntlmssp.c`, подэтап 4d): домен, версия ОС и NTLM,
//! список AV_PAIR TargetInfo в запись `smb` (`PROTO_SMB`).
//!
//! Безопасная реализация (Р2, Р13):
//! - Буферизует ровно `expected_len` байт (ограничено 65 536 байт, как у C `ntlmssp_decode_init`).
//! - Разбирает пакет ровно один раз при получении всех `expected_len` байт, независимо от нарезки
//!   потока на сегменты (Р13).
//! - Все смещения и длины (`name_offset`, `name_length`, `info_offset`, `info_length`, длина AV_PAIR)
//!   проверяются через `checked_add` и `get(..)`: устраняет C-переполнение `info_offset = 0xFFFFFFFC`
//!   (`proto-ntlmssp.c:182`) и двойной `free` буфера.

use crate::app::app_id;

use super::session::ParseCx;

/// Максимальный размер буфера NTLMSSP (`src/proto-ntlmssp.c:262`).
const MAX_NTLMSSP_LEN: usize = 65_536;

/// Потоковый декодер NTLMSSP Type-2 Challenge.
#[derive(Debug, Default)]
pub(crate) struct Ntlmssp {
    expected_len: usize,
    buf: Vec<u8>,
    done: bool,
}

impl Ntlmssp {
    /// `ntlmssp_decode_init`: подготавливает декодер к приёму `length` байт (не больше 65 536).
    pub(crate) fn init(&mut self, length: usize) {
        self.expected_len = length.min(MAX_NTLMSSP_LEN);
        self.buf.clear();
        self.done = self.expected_len == 0;
    }

    /// Очищает буфер (при начале нового NBT-кадра или завершении responseToken).
    pub(crate) fn clear(&mut self) {
        self.expected_len = 0;
        self.buf.clear();
        self.done = true;
    }

    /// Подаёт очередной фрагмент байт NTLMSSP; когда собрано `expected_len`, разбирает сообщение.
    pub(crate) fn feed(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        if self.done || px.is_empty() {
            return;
        }
        let need = self.expected_len.saturating_sub(self.buf.len());
        if need == 0 {
            self.done = true;
            return;
        }
        let take = px.len().min(need);
        if self.buf.is_empty() && take == self.expected_len {
            // Быстрый путь: весь NTLMSSP пришёл за один вызов, без копирования.
            self.done = true;
            decode_challenge(cx, &px[..take]);
            return;
        }
        self.buf.extend_from_slice(&px[..take]);
        if self.buf.len() >= self.expected_len {
            self.done = true;
            let data = std::mem::take(&mut self.buf);
            decode_challenge(cx, &data);
        }
    }
}

/// Записывает `" <name>=<utf16le>"` в запись `PROTO_SMB` (как `append_unicode_string` в `proto-ntlmssp.c:93-103`).
fn append_unicode_string(cx: &mut ParseCx<'_>, name: &[u8], value: &[u8]) {
    cx.append(app_id::SMB, b" ");
    cx.append(app_id::SMB, name);
    cx.append(app_id::SMB, b"=");
    for &pair in value.as_chunks::<2>().0 {
        let code = u32::from(u16::from_le_bytes(pair));
        cx.append_unicode(app_id::SMB, code);
    }
}

/// Разбирает целый NTLMSSP Type-2 Challenge (`proto-ntlmssp.c:139-226`) с полной проверкой границ.
fn decode_challenge(cx: &mut ParseCx<'_>, px: &[u8]) {
    if px.len() < 56 {
        return;
    }
    if &px[..8] != b"NTLMSSP\0" {
        return;
    }
    let message_type = u32::from_le_bytes([px[8], px[9], px[10], px[11]]);
    if message_type != 2 {
        return;
    }

    // TargetName (Domain)
    let name_length = usize::from(u16::from_le_bytes([px[12], px[13]]));
    let name_offset = u32::from_le_bytes([px[16], px[17], px[18], px[19]]) as usize;
    if name_length > 0
        && let Some(end) = name_offset.checked_add(name_length)
        && let Some(slice) = px.get(name_offset..end)
    {
        append_unicode_string(cx, b"domain", slice);
    }

    // TargetInfo bounds
    let info_length = usize::from(u16::from_le_bytes([px[40], px[41]]));
    let info_offset = u32::from_le_bytes([px[44], px[45], px[46], px[47]]) as usize;

    // Version field (bytes 48..56)
    let major = px[48];
    let minor = px[49];
    let build = u16::from_le_bytes([px[50], px[51]]);
    let ntlm_ver = px[55];
    let ver = format!(" version={major}.{minor}.{build} ntlm-ver={ntlm_ver}");
    cx.append(app_id::SMB, ver.as_bytes());

    // AV_PAIR TargetInfo list (safe checked bounds — no u32 wraparound as in C :182)
    let Some(info_end) = info_offset
        .checked_add(info_length)
        .map(|e| e.min(px.len()))
    else {
        return;
    };
    let mut i = info_offset;
    // Matches C `i + 4 < info_offset + info_length && i + 4 < length` when info_offset <= info_end:
    // note C used `<` (strict), so a 4-byte MsvAvEOL at the exact end of the buffer is not entered,
    // which produces the same output because MsvAvEOL prints nothing; using `<=` also handles
    // 0-length AV_PAIRs at the exact end cleanly if they have a name, wait — let's check C:
    // In C (`proto-ntlmssp.c:182`): `i + 4 < info_offset + info_length && i + 4 < length`
    // So if an AV_PAIR has length 0 at the exact end of TargetInfo (e.g. MsvAvEOL 00 00 00 00),
    // the loop exits before reading it. Keeping `i + 4 < info_end` matches C exactly.
    while i.checked_add(4).is_some_and(|hdr_end| hdr_end < info_end) {
        let av_type = u16::from_le_bytes([px[i], px[i + 1]]);
        let av_len = usize::from(u16::from_le_bytes([px[i + 2], px[i + 3]]));
        i += 4;
        let len = av_len.min(info_end - i);
        let val = &px[i..i + len];
        match av_type {
            0x0000 => break, // MsvAvEOL
            1 => append_unicode_string(cx, b"name", val),
            2 => append_unicode_string(cx, b"domain", val),
            3 => append_unicode_string(cx, b"name-dns", val),
            4 => append_unicode_string(cx, b"domain-dns", val),
            5 => append_unicode_string(cx, b"forest", val),
            9 => append_unicode_string(cx, b"target", val),
            _ => {}
        }
        i += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner1::banout::{Banout, Base64Stream};
    use crate::banner1::tls::TlsFlags;
    use crate::tcp::app::ByteBudget;
    use std::sync::Arc;

    fn run_ntlmssp(segs: &[&[u8]]) -> Vec<(u16, Vec<u8>)> {
        let total: usize = segs.iter().map(|s| s.len()).sum();
        let mut n = Ntlmssp::default();
        n.init(total);
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
            n.feed(&mut cx, seg);
        }
        banout.flush(&mut budget)
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Синтетический NTLMSSP Type-2 Challenge со всеми полями (domain, version, AV_PAIR 1..5, 9) целиком и побайтово.
    #[test]
    fn parses_type2_challenge_in_all_splits() {
        let target_name = utf16le("CORP");
        let mut av = Vec::new();
        for (id, val) in [
            (2u16, "CORP"),
            (1, "SRV01"),
            (4, "corp.local"),
            (3, "srv01.corp.local"),
            (5, "forest.local"),
            (9, "cifs/srv01"),
            (0, ""),
        ] {
            let v = utf16le(val);
            av.extend_from_slice(&id.to_le_bytes());
            av.extend_from_slice(&(v.len() as u16).to_le_bytes());
            av.extend_from_slice(&v);
        }

        let name_off: u32 = 56;
        let info_off: u32 = name_off + target_name.len() as u32;
        let mut msg = vec![0u8; 56];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[12..14].copy_from_slice(&(target_name.len() as u16).to_le_bytes());
        msg[14..16].copy_from_slice(&(target_name.len() as u16).to_le_bytes());
        msg[16..20].copy_from_slice(&name_off.to_le_bytes());
        msg[40..42].copy_from_slice(&(av.len() as u16).to_le_bytes());
        msg[42..44].copy_from_slice(&(av.len() as u16).to_le_bytes());
        msg[44..48].copy_from_slice(&info_off.to_le_bytes());
        msg[48] = 10;
        msg[49] = 0;
        msg[50..52].copy_from_slice(&19041u16.to_le_bytes());
        msg[55] = 15;
        msg.extend_from_slice(&target_name);
        msg.extend_from_slice(&av);

        let want = b" domain=CORP version=10.0.19041 ntlm-ver=15 domain=CORP name=SRV01 domain-dns=corp.local name-dns=srv01.corp.local forest=forest.local target=cifs/srv01".to_vec();
        let whole = run_ntlmssp(&[&msg]);
        assert_eq!(whole, [(app_id::SMB, want)]);

        let bytewise: Vec<&[u8]> = msg.chunks(1).collect();
        assert_eq!(run_ntlmssp(&bytewise), whole);
    }

    /// Р2: `info_offset = 0xFFFFFFFC` (в C оборачивает `i + 4` до `0` и читает память за пределами) не паникует и
    /// не читает вне буфера.
    #[test]
    fn info_offset_wraparound_is_safe() {
        let mut msg = vec![0u8; 64];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[40..42].copy_from_slice(&32u16.to_le_bytes());
        msg[44..48].copy_from_slice(&0xFFFF_FFFCu32.to_le_bytes());
        msg[48] = 6;
        msg[49] = 1;
        msg[50..52].copy_from_slice(&7601u16.to_le_bytes());
        msg[55] = 15;

        let got = run_ntlmssp(&[&msg]);
        assert_eq!(
            got,
            [(app_id::SMB, b" version=6.1.7601 ntlm-ver=15".to_vec())]
        );
    }
}
