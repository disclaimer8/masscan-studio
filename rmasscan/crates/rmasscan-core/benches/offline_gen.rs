//! Бенчмарк генерации без criterion (AGPL-3.0, masscan © Robert David Graham).
//! criterion =0.8.2 тянет `alloca` -> `cc` (C-компилятор) в dev-граф, что
//! нарушает правило «без C в графе», поэтому здесь простой замер по времени.
//!
//! Конвейер тот же, что в `tests/offline_gen.rs` (`transmit_scan` + cookie +
//! `build_syn`). Запуск: `cargo bench -p rmasscan-core` (3 прогона, /10 x 1 порт).
//! Сравнение с оракулом C — только `tests/offline_gen.rs` на minipc.

#[path = "../tests/common/offline_gen.rs"]
mod offline_gen;

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let m = offline_gen::build_massip("0.0.0.0/10", "80");
    for run in 1..=3 {
        let start = Instant::now();
        let (n, sink) = black_box(offline_gen::generate(black_box(&m)));
        let secs = start.elapsed().as_secs_f64();
        println!(
            "offline_gen run {run}: {n} packets in {secs:.3} s = {:.0} pps (sink {sink})",
            n as f64 / secs
        );
    }
}
