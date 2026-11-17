//! Счётчики `NetStats` адаптеров.
//!
//! Блок TX и блок RX лежат на разных строках кэша (`align(128)`: парная строка
//! префетчера на x86-64 и 128-байтовая строка Apple Silicon), поэтому два потока
//! не гоняют одну строку между ядрами. Писатель у каждого счётчика один: сторона
//! ([`TxSide`] или [`RxSide`]) не `Clone`, её методы записи берут `&mut self`, а
//! запись в `Counter` вне этого модуля не видна. Поэтому запись это
//! `store(load + n)`, а не `fetch_add`: чтение-изменение-запись без блокировки шины
//! безопасно, пока писатель один. Читает любой поток через [`Counters::snapshot`].
#![cfg_attr(
    not(any(target_os = "linux", windows, target_os = "macos")),
    allow(dead_code)
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(any(windows, target_os = "macos", test))]
use std::sync::atomic::Ordering::Release;

use rmasscan_engine::SendStatus;

use crate::NetStats;

/// Один счётчик. Запись только с одного потока (гарантируют стороны ниже).
#[derive(Default)]
struct Counter(AtomicU64);

impl Counter {
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn add(&self, n: u64) {
        self.0.store(self.get().wrapping_add(n), Ordering::Relaxed);
    }

    #[cfg(any(windows, test))]
    fn max(&self, n: u64) {
        self.0.store(self.get().max(n), Ordering::Relaxed);
    }

    #[cfg(any(windows, target_os = "macos", test))]
    fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
}

#[derive(Default)]
#[repr(align(128))]
struct TxCounters {
    sent: Counter,
    would_block: Counter,
    uncertain: Counter,
    errors: Counter,
    batches: Counter,
    batch_max: Counter,
    over_budget: Counter,
}

#[derive(Default)]
#[repr(align(128))]
struct RxCounters {
    packets: Counter,
    truncated: Counter,
    outgoing: Counter,
    wrong_interface: Counter,
    errors: Counter,
    kernel_drops: Counter,
    kernel_drops_known: AtomicBool,
}

#[derive(Default)]
pub(crate) struct Counters {
    tx: TxCounters,
    rx: RxCounters,
}

impl Counters {
    /// Снимок для любого потока; ничего не сбрасывает.
    pub(crate) fn snapshot(&self) -> NetStats {
        let (t, r) = (&self.tx, &self.rx);
        NetStats {
            tx_sent: t.sent.get(),
            tx_would_block: t.would_block.get(),
            tx_uncertain: t.uncertain.get(),
            tx_errors: t.errors.get(),
            rx_packets: r.packets.get(),
            rx_truncated: r.truncated.get(),
            rx_outgoing: r.outgoing.get(),
            rx_wrong_interface: r.wrong_interface.get(),
            rx_errors: r.errors.get(),
            kernel_drops: r
                .kernel_drops_known
                .load(Ordering::Acquire)
                .then(|| r.kernel_drops.get()),
            tx_batches: t.batches.get(),
            tx_batch_max: t.batch_max.get(),
            tx_over_budget: t.over_budget.get(),
        }
    }
}

/// Единственный конструктор сторон: по одной TX и одной RX, общий `Arc` для снимков.
pub(crate) fn counters() -> (TxSide, RxSide, Arc<Counters>) {
    let shared = Arc::new(Counters::default());
    (
        TxSide(Arc::clone(&shared)),
        RxSide(Arc::clone(&shared)),
        shared,
    )
}

/// Сторона записи TX. Не `Clone`: второго писателя блока TX не бывает.
pub(crate) struct TxSide(Arc<Counters>);

impl TxSide {
    pub(crate) fn sent(&mut self, n: u64) {
        self.0.tx.sent.add(n);
    }

    #[cfg(any(not(windows), test))]
    pub(crate) fn would_block(&mut self) {
        self.0.tx.would_block.add(1);
    }

    pub(crate) fn uncertain(&mut self, n: u64) {
        self.0.tx.uncertain.add(n);
    }

    pub(crate) fn error(&mut self) {
        self.0.tx.errors.add(1);
    }

    /// Одна пачка из `n` кадров: `batches + 1`, `batch_max` не меньше `n`.
    #[cfg(any(windows, test))]
    pub(crate) fn batch(&mut self, n: u64) {
        self.0.tx.batches.add(1);
        self.0.tx.batch_max.max(n);
    }

    #[cfg(any(windows, test))]
    pub(crate) fn over_budget(&mut self) {
        self.0.tx.over_budget.add(1);
    }

    #[cfg(any(not(windows), test))]
    pub(crate) fn record(&mut self, s: SendStatus) {
        match s {
            SendStatus::Sent => self.sent(1),
            SendStatus::WouldBlockUnsent => self.would_block(),
            SendStatus::Uncertain => self.uncertain(1),
        }
    }
}

/// Сторона записи RX. Не `Clone`: второго писателя блока RX не бывает.
pub(crate) struct RxSide(Arc<Counters>);

impl RxSide {
    pub(crate) fn packet(&mut self) {
        self.0.rx.packets.add(1);
    }

    pub(crate) fn truncated(&mut self) {
        self.0.rx.truncated.add(1);
    }

    pub(crate) fn outgoing(&mut self) {
        self.0.rx.outgoing.add(1);
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn wrong_interface(&mut self) {
        self.0.rx.wrong_interface.add(1);
    }

    pub(crate) fn error(&mut self) {
        self.0.rx.errors.add(1);
    }

    /// Linux: ядро сбрасывает свой счётчик при чтении, поэтому дельта копится здесь.
    /// Возвращает накопленный итог.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn add_kernel_drops(&mut self, delta: u64) -> u64 {
        let rx = &self.0.rx;
        rx.kernel_drops.add(delta);
        rx.kernel_drops_known.store(true, Ordering::Release);
        rx.kernel_drops.get()
    }

    /// macOS и Windows: драйвер отдаёт накопленный итог, он просто публикуется.
    #[cfg(any(windows, target_os = "macos", test))]
    pub(crate) fn publish_drops(&mut self, total: u64) {
        let rx = &self.0.rx;
        rx.kernel_drops.set(total);
        rx.kernel_drops_known.store(true, Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of};

    #[test]
    fn counter_blocks_live_on_separate_cache_lines() {
        assert_eq!(align_of::<TxCounters>(), 128);
        assert_eq!(align_of::<RxCounters>(), 128);
        assert!(offset_of!(Counters, rx).abs_diff(offset_of!(Counters, tx)) >= 128);
    }

    #[test]
    fn tx_side_writes_only_its_block_and_snapshot_reads_all() {
        let (mut t, mut r, c) = counters();
        t.sent(3);
        t.record(SendStatus::Sent);
        t.record(SendStatus::WouldBlockUnsent);
        t.record(SendStatus::Uncertain);
        t.uncertain(2);
        t.error();
        t.batch(5);
        t.batch(3);
        t.over_budget();
        assert_eq!(
            c.snapshot(),
            NetStats {
                tx_sent: 4,
                tx_would_block: 1,
                tx_uncertain: 3,
                tx_errors: 1,
                tx_batches: 2,
                tx_batch_max: 5,
                tx_over_budget: 1,
                ..NetStats::default()
            }
        );
        r.packet();
        r.truncated();
        r.outgoing();
        r.wrong_interface();
        r.error();
        assert_eq!(
            c.snapshot(),
            NetStats {
                tx_sent: 4,
                tx_would_block: 1,
                tx_uncertain: 3,
                tx_errors: 1,
                tx_batches: 2,
                tx_batch_max: 5,
                tx_over_budget: 1,
                rx_packets: 1,
                rx_truncated: 1,
                rx_outgoing: 1,
                rx_wrong_interface: 1,
                rx_errors: 1,
                kernel_drops: None,
            }
        );
    }

    #[test]
    fn kernel_drops_stay_unknown_until_published_and_accumulate_or_overwrite() {
        let (_, mut r, c) = counters();
        assert_eq!(c.snapshot().kernel_drops, None);
        assert_eq!(r.add_kernel_drops(0), 0);
        assert_eq!(c.snapshot().kernel_drops, Some(0));
        assert_eq!(r.add_kernel_drops(4), 4);
        assert_eq!(r.add_kernel_drops(3), 7);
        r.publish_drops(2);
        assert_eq!(c.snapshot().kernel_drops, Some(2));
    }
}
