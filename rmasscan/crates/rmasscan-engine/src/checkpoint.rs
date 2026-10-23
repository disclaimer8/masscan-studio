//! Версионированный checkpoint (AGPL-3.0).
//!
//! Checkpoint это ДАННЫЕ о том, откуда продолжить ту же последовательность.
//! Это не сохранённая пауза: durable Paused подтверждает Studio после commit и
//! ACK, движок ничего не пишет на диск.
//!
//! # Бинарный вид (версия формата 1, big-endian, 120 байт)
//! ```text
//! "RMSCNCKP" | u32 format_version | u32 engine_version | scan_id[16] |
//! attempt_id[16] | job_digest[32] | u64 next_index | sha256(всё выше)[32]
//! ```
//! Хвостовая сумма ловит случайное повреждение любого поля при чтении; от
//! злонамеренной подмены она не защищает (подлинность это дело Studio).

use sha2::{Digest, Sha256};

/// Версия формата checkpoint.
pub const CHECKPOINT_FORMAT_VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"RMSCNCKP";
/// Длина бинарного вида.
pub const CHECKPOINT_LEN: usize = 8 + 4 + 4 + 16 + 16 + 32 + 8 + 32;

/// Ошибки checkpoint и resume. Все возникают ДО первой отправки.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint is malformed: {0}")]
    Malformed(&'static str),
    #[error("checkpoint checksum mismatch (corrupted)")]
    BadChecksum,
    #[error("unsupported checkpoint format version {0}")]
    UnsupportedFormat(u32),
    #[error("checkpoint was made by engine algorithm version {0}, this is {1}")]
    EngineVersionMismatch(u32, u32),
    #[error("checkpoint belongs to a different job (identity digest differs)")]
    JobMismatch,
    #[error("checkpoint scan_id does not match the scan_id of this resume")]
    ScanIdMismatch,
    #[error("a resumed run must have a fresh attempt_id, not the checkpoint's")]
    AttemptIdReused,
    #[error(
        "checkpoint next_index {0} equals the range: the scan already completed, nothing to resume"
    )]
    AlreadyCompleted(u64),
}

/// Точка продолжения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub format_version: u32,
    /// `ENGINE_ALGORITHM_VERSION` движка, сделавшего checkpoint.
    pub engine_version: u32,
    /// Сохраняется при resume.
    pub scan_id: [u8; 16],
    /// Попытка, СОЗДАВШАЯ checkpoint (происхождение). Текущая попытка resume
    /// обязана иметь другой attempt_id.
    pub attempt_id: [u8; 16],
    pub job_digest: [u8; 32],
    /// Следующий неподтверждённый индекс probe.
    pub next_index: u64,
}

impl Checkpoint {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(CHECKPOINT_LEN);
        o.extend_from_slice(MAGIC);
        o.extend_from_slice(&self.format_version.to_be_bytes());
        o.extend_from_slice(&self.engine_version.to_be_bytes());
        o.extend_from_slice(&self.scan_id);
        o.extend_from_slice(&self.attempt_id);
        o.extend_from_slice(&self.job_digest);
        o.extend_from_slice(&self.next_index.to_be_bytes());
        let sum = Sha256::digest(&o);
        o.extend_from_slice(&sum);
        o
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, CheckpointError> {
        if b.len() != CHECKPOINT_LEN {
            return Err(CheckpointError::Malformed("wrong length"));
        }
        let (body, sum) = b.split_at(CHECKPOINT_LEN - 32);
        if Sha256::digest(body).as_slice() != sum {
            return Err(CheckpointError::BadChecksum);
        }
        if &body[..8] != MAGIC {
            return Err(CheckpointError::Malformed("bad magic"));
        }
        let u32_at =
            |i: usize| u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        let arr16 = |i: usize| -> [u8; 16] { body[i..i + 16].try_into().unwrap_or([0; 16]) };
        let format_version = u32_at(8);
        if format_version != CHECKPOINT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedFormat(format_version));
        }
        Ok(Self {
            format_version,
            engine_version: u32_at(12),
            scan_id: arr16(16),
            attempt_id: arr16(32),
            job_digest: body[48..80].try_into().unwrap_or([0; 32]),
            next_index: u64::from_be_bytes(body[80..88].try_into().unwrap_or([0; 8])),
        })
    }
}
