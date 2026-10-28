//! Идентичность задания: SHA-256 над версионированной канонической бинарной
//! кодировкой (AGPL-3.0).
//!
//! # Кодировка (версия формата 1)
//! Всё целое это big-endian фиксированной ширины; любое поле переменной длины
//! имеет префикс длины `u32`; списки имеют префикс-счётчик `u32`. Поэтому
//! разбор однозначен: нет разделителей и нет склейки строк, два разных задания
//! не могут дать один и тот же байтовый поток.
//!
//! ```text
//! "RMSCNJOB"                 8 байт, магия
//! u32 ENGINE_ALGORITHM_VERSION
//! список диапазонов: source_targets.ipv4, source_targets.ports,
//!                    source_excludes.ipv4, source_excludes.ports
//!     каждый: u32 n, затем n * (u32 begin, u32 end)
//! u64 seed
//! u64 rate (IEEE-754 биты f64; 0.0 и -0.0 сведены в 0)
//! u32 retries, u32 shard.one, u32 shard.of, u32 blackrock_rounds
//! u32 wait_secs
//! binding: u32 len + interface_id (UTF-8), u8 link_type (Ethernet 1, Null 2,
//!     Raw 3), u32 source_ipv4, [u8;6] source_mac, [u8;6] next_hop_mac,
//!     u16 first_port, u16 last_port
//! ```
//! Диапазоны берутся из нормализованных `source_targets()` / `source_excludes()`
//! (после `optimize`), а не из итогового `massip` (его вид зависит от
//! исключений). `ENGINE_ALGORITHM_VERSION` это явная версия алгоритма и
//! формата: её повышают вручную при изменении порядка probe, формулы кадра или
//! этой кодировки. Она НЕ зависит от commit и комментариев.
//!
//! Mapped plans use a separate domain: `RMSCNMAP`, u32 map format version (1),
//! u64 legacy encoding length, the unchanged legacy encoding, u64 entry count,
//! then sorted `(u32 IPv4, [u8;6] MAC)` entries. Integers are big-endian.
//! Single-MAC plans retain the exact version-1 encoding and digest above.

use rmasscan_core::config::EffectiveConfig;
use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::{AdapterBinding, ReadyPlan};
use rmasscan_core::ranges::RangeList;
use sha2::{Digest, Sha256};

/// Версия алгоритма генерации последовательности и формата идентичности.
pub const ENGINE_ALGORITHM_VERSION: u32 = 1;
/// Магия кодировки задания.
pub const JOB_MAGIC: &[u8; 8] = b"RMSCNJOB";

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_ranges(out: &mut Vec<u8>, list: &RangeList) {
    let s = list.as_slice();
    put_u32(out, u32::try_from(s.len()).unwrap_or(u32::MAX));
    for r in s {
        put_u32(out, r.begin);
        put_u32(out, r.end);
    }
}

fn link_tag(l: LinkType) -> u8 {
    match l {
        LinkType::Ethernet => 1,
        LinkType::Null => 2,
        LinkType::Raw => 3,
    }
}

/// Legacy single-MAC encoding. For mapped plans, [`job_digest`] frames this
/// encoding in the separate map domain together with the complete destination map.
pub fn canonical_job_bytes(effective: &EffectiveConfig, binding: &AdapterBinding) -> Vec<u8> {
    let mut o = Vec::with_capacity(256);
    o.extend_from_slice(JOB_MAGIC);
    put_u32(&mut o, ENGINE_ALGORITHM_VERSION);
    put_ranges(&mut o, effective.source_targets().ipv4());
    put_ranges(&mut o, effective.source_targets().ports());
    put_ranges(&mut o, effective.source_excludes().ipv4());
    put_ranges(&mut o, effective.source_excludes().ports());
    put_u64(&mut o, effective.seed());
    let rate = effective.max_rate();
    put_u64(&mut o, if rate == 0.0 { 0 } else { rate.to_bits() });
    put_u32(&mut o, effective.retries());
    put_u32(&mut o, effective.shard().one);
    put_u32(&mut o, effective.shard().of);
    put_u32(&mut o, effective.blackrock_rounds());
    put_u32(&mut o, effective.wait_secs());
    let id = binding.interface_id.as_bytes();
    put_u32(&mut o, u32::try_from(id.len()).unwrap_or(u32::MAX));
    o.extend_from_slice(id);
    o.push(link_tag(binding.link_type));
    put_u32(&mut o, binding.source_ipv4);
    o.extend_from_slice(&binding.source_mac);
    o.extend_from_slice(&binding.next_hop_mac);
    o.extend_from_slice(&binding.source_ports.0.to_be_bytes());
    o.extend_from_slice(&binding.source_ports.1.to_be_bytes());
    o
}

/// SHA-256 канонической кодировки.
pub fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Идентичность задания плана.
pub fn job_digest(plan: &ReadyPlan) -> [u8; 32] {
    let legacy = canonical_job_bytes(plan.effective(), plan.binding());
    let Some(destinations) = plan.destinations() else {
        return digest_bytes(&legacy);
    };
    let mut digest = Sha256::new();
    digest.update(b"RMSCNMAP");
    digest.update(1u32.to_be_bytes());
    digest.update((legacy.len() as u64).to_be_bytes());
    digest.update(&legacy);
    digest.update((destinations.len() as u64).to_be_bytes());
    for (ip, mac) in destinations {
        digest.update(ip.to_be_bytes());
        digest.update(mac);
    }
    digest.finalize().into()
}
