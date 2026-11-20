//! Дайджест потока для страховки рефакторинга (AGPL-3.0, masscan © Robert David Graham): SHA-256 (`common::Sha256`)
//! над полями в фиксированной раскладке. Числа little-endian, байты и строки с длиной `u32` впереди, цель с байтом
//! семейства (4 или 6) и адресом `u128`. Раскладка не зависит от `Debug` типов ядра, кроме мест, где тест сам кладёт
//! текст (`text`).
#![allow(dead_code)]

use rmasscan_core::massip::TargetIp;
use rmasscan_core::probe::Probe;

use crate::common::Sha256;

pub struct Digest {
    h: Sha256,
}

impl Default for Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Digest {
    pub fn new() -> Self {
        Digest { h: Sha256::new() }
    }

    pub fn u16(&mut self, v: u16) {
        self.h.update(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.h.update(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.h.update(&v.to_le_bytes());
    }

    /// Длина `u32` LE, затем байты.
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.h.update(b);
    }

    /// Как [`Digest::bytes`] над UTF-8 строки.
    pub fn text(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    /// Байт семейства (4 или 6), затем адрес как `u128` LE.
    pub fn target(&mut self, t: TargetIp) {
        let (family, addr) = match t {
            TargetIp::V4(ip) => (4u8, u128::from(ip)),
            TargetIp::V6(ip) => (6u8, ip),
        };
        self.h.update(&[family]);
        self.h.update(&addr.to_le_bytes());
    }

    /// Поля зонда по порядку: `index, ip_me, port_me, ip_them, target, port_them, port_index, seqno, frame`.
    pub fn probe(&mut self, p: &Probe) {
        self.u64(p.index);
        self.u32(p.ip_me);
        self.u16(p.port_me);
        self.u32(p.ip_them);
        self.target(p.target);
        self.u16(p.port_them);
        self.u32(p.port_index);
        self.u32(p.seqno);
        self.bytes(&p.frame);
    }

    /// Hex SHA-256.
    pub fn finish(self) -> String {
        self.h.finish()
    }
}
