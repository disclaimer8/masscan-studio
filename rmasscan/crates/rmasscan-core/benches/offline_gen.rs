//! Бенчмарк генерации без criterion (AGPL-3.0, masscan © Robert David Graham).
//! criterion =0.8.2 тянет `alloca` -> `cc` (C-компилятор) в dev-граф, что
//! нарушает правило «без C в графе», поэтому здесь простой замер по времени.
//!
//! Конвейер тот же, что в `tests/offline_gen.rs` (`transmit_scan` + cookie +
//! `build_syn`). Запуск: `cargo bench -p rmasscan-core` (3 прогона, /10 x 1 порт;
//! циклы `cursor_*` идут через `ProbeCursor`, как движок).
//! Сравнение с оракулом C — только `tests/offline_gen.rs` на хосте стенда (bench host).

#[path = "../tests/common/offline_gen.rs"]
mod offline_gen;

use std::hint::black_box;
use std::time::Instant;

/// Три прогона цикла: pps и sink в строке `<name> run k: ...`.
fn run3(name: &str, mut f: impl FnMut() -> (u64, u64)) {
    for run in 1..=3 {
        let start = Instant::now();
        let (n, sink) = black_box(f());
        let secs = start.elapsed().as_secs_f64();
        println!(
            "{name} run {run}: {n} packets in {secs:.3} s = {:.0} pps (sink {sink})",
            n as f64 / secs
        );
    }
}

fn main() {
    let m = offline_gen::build_massip("0.0.0.0/10", "80");
    run3("offline_gen", || offline_gen::generate(black_box(&m)));
    let one = offline_gen::cursor_plan("0.0.0.0/10", "80", (40000, 40000));
    run3("cursor_1port", || {
        offline_gen::generate_cursor(black_box(&one), 64)
    });
    let sixteen = offline_gen::cursor_plan("0.0.0.0/10", "80", (40000, 40015));
    run3("cursor_16port", || {
        offline_gen::generate_cursor(black_box(&sixteen), 64)
    });
    let mapped = offline_gen::mapped_plan("10.0.0.0/16", "1-64");
    run3("cursor_mapped", || {
        offline_gen::generate_cursor(black_box(&mapped), 64)
    });
}
