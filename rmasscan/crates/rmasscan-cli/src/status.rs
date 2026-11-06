//!
//! Три режима: текст (`rate:%6.2f-kpps, %5.2f%% done,%4u:%02u:%02u remaining, found=%u       \r`, `main-status.c:
//! 244–265`), NDJSON (`--ndjson-status`, `main-status.c:56–125`) и выключено (`--nostatus`). Печатаемые kpps и pps
//! это мгновенная скорость throttle (`Progress.rate`), как `pps / 1000.0` в C; сглаженная по 8 отсчётам скорость
//! `(count - last_count) / elapsed` идёт только в оценку оставшегося времени. Строка печатается только живым
//! сканом (`run_live`); `--readscan`, `-sL`, `--echo`, `--offline` и `--iflist` её не знают.
//!
//! Отличия от C там, где C печатает мусор: при `max_count == 0` процент считается равным 100 (а не NaN), а оставшееся
//! время при нулевой, нечисловой или бесконечной сглаженной скорости и при проценте выше 100 зажимается в 0 (в C это
//! `inf`, приведённое к `unsigned`). Часы `last.clock` в C это `clock()` в тиках процессора против микросекунд
//! `pixie_gettime()`; здесь начало отсчёта это момент старта скана на часах бэкенда.

#![forbid(unsafe_code)]

use std::io::{self, Write};

/// Что печатает [`StatusLine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusMode {
    /// `rate: …\r` в stderr (по умолчанию и `--status`).
    Text,
    /// Одна JSON-строка на отсчёт (`--ndjson-status`).
    Ndjson,
    /// Ничего (`--nostatus`).
    Off,
}

/// Период печати в фазе передачи (`pixie_mssleep(750)`, `main.c:1442`) и в фазе ожидания (`pixie_mssleep(250)`,
/// `main.c:1511`).
const TX_INTERVAL_MICROS: u64 = 750_000;
const WAIT_INTERVAL_MICROS: u64 = 250_000;

/// Состояние `struct Status` C: момент и счётчик прошлой печати и кольцо из 8 скоростей (изначально нули).
#[derive(Debug)]
pub struct StatusLine {
    mode: StatusMode,
    last_clock: u64,
    last_count: u64,
    printed: bool,
    rates: [f64; 8],
    samples: usize,
}

impl StatusLine {
    /// `start_micros`: момент старта скана на часах бэкенда (`status_start`).
    pub fn new(mode: StatusMode, start_micros: u64) -> StatusLine {
        StatusLine {
            mode,
            last_clock: start_micros,
            last_count: 0,
            printed: false,
            rates: [0.0; 8],
            samples: 0,
        }
    }

    /// Один отсчёт (`status_print`). `count` это следующий индекс probe, `max_count` весь диапазон, `pps` текущая
    /// скорость throttle, `found` число open-ответов, `exiting` секунды до конца ожидания (`Some` после конца
    /// передачи). Печатает не чаще раза в 750 мс при передаче и 250 мс при ожидании; при `elapsed <= 0` молчит.
    #[allow(clippy::too_many_arguments)]
    pub fn tick(
        &mut self,
        now_micros: u64,
        count: u64,
        max_count: u64,
        pps: f64,
        found: u64,
        exiting: Option<i64>,
        log: &mut dyn Write,
    ) -> io::Result<()> {
        if self.mode == StatusMode::Off {
            return Ok(());
        }
        let interval = if exiting.is_some() {
            WAIT_INTERVAL_MICROS
        } else {
            TX_INTERVAL_MICROS
        };
        if self.printed && now_micros.saturating_sub(self.last_clock) < interval {
            return Ok(());
        }
        if now_micros <= self.last_clock {
            return Ok(());
        }
        let elapsed = (now_micros - self.last_clock) as f64 / 1_000_000.0;
        let rate = count.saturating_sub(self.last_count) as f64 / elapsed;
        self.rates[self.samples & 7] = rate;
        self.samples += 1;
        let smoothed = self.rates.iter().sum::<f64>() / 8.0;
        let percent = if max_count == 0 {
            100.0
        } else {
            count as f64 * 100.0 / max_count as f64
        };
        let remaining = (1.0 - percent / 100.0) * (max_count as f64 / smoothed);
        let line = match (self.mode, exiting) {
            (StatusMode::Text, None) => running_line(pps / 1000.0, percent, remaining, found),
            (StatusMode::Text, Some(e)) => waiting_line(pps / 1000.0, percent, e, found),
            (_, None) => ndjson_running(pps, percent, remaining, found, count, max_count),
            (_, Some(e)) => ndjson_waiting(pps, percent, e, found, count, max_count),
        };
        log.write_all(line.as_bytes())?;
        log.flush()?;
        self.last_clock = now_micros;
        self.last_count = count;
        self.printed = true;
        Ok(())
    }

    /// `status_finish`: 77 пробелов и `\r`, затирают строку. Ничего в режимах `Ndjson` и `Off`.
    pub fn finish(&mut self, log: &mut dyn Write) -> io::Result<()> {
        if self.mode != StatusMode::Text {
            return Ok(());
        }
        log.write_all(format!("{}\r", " ".repeat(77)).as_bytes())?;
        log.flush()
    }
}

/// Часы, минуты, секунды остатка как `(unsigned)(t/3600)`, `(unsigned)(t/60) % 60`, `(unsigned)t % 60`.
fn hms(remaining: f64) -> (u32, u32, u32) {
    let remaining = if remaining.is_finite() && remaining > 0.0 {
        remaining
    } else {
        0.0
    };
    (
        (remaining / 3600.0) as u32,
        (remaining / 60.0) as u32 % 60,
        remaining as u32 % 60,
    )
}

/// Фаза передачи, текст (`main-status.c:262`).
pub fn running_line(kpps: f64, percent: f64, remaining_secs: f64, found: u64) -> String {
    let (h, m, s) = hms(remaining_secs);
    format!(
        "rate:{kpps:6.2}-kpps, {percent:5.2}% done,{h:4}:{m:02}:{s:02} remaining, found={found}       \r"
    )
}

/// Фаза ожидания, текст (`main-status.c:249`).
pub fn waiting_line(kpps: f64, percent: f64, exiting: i64, found: u64) -> String {
    format!(
        "rate:{kpps:6.2}-kpps, {percent:5.2}% done, waiting {exiting}-secs, found={found}       \r"
    )
}

/// Фаза передачи, NDJSON (`json_fmt_running`). kpps это `pps / 1000`.
pub fn ndjson_running(
    pps: f64,
    percent: f64,
    remaining_secs: f64,
    found: u64,
    count: u64,
    max_count: u64,
) -> String {
    let (h, m, s) = hms(remaining_secs);
    format!(
        "{{\"state\":\"running\",\"rate\":{{\"kpps\":{:.2},\"pps\":{pps:.2}}},\"progress\":{{\"percent\":{percent:.2},\"eta\":{{\"hours\":{h},\"mins\":{m},\"seconds\":{s}}},\"syn\":{{\"sent\":{count},\"total\":{max_count},\"remaining\":{}}},\"found\":{found}}}}}\n",
        pps / 1000.0,
        max_count.saturating_sub(count)
    )
}

/// Фаза ожидания, NDJSON (`json_fmt_waiting`).
pub fn ndjson_waiting(
    pps: f64,
    percent: f64,
    exiting: i64,
    found: u64,
    count: u64,
    max_count: u64,
) -> String {
    format!(
        "{{\"state\":\"waiting\",\"rate\":{{\"kpps\":{:.2},\"pps\":{pps:.2}}},\"progress\":{{\"percent\":{percent:.2},\"seconds\":{exiting},\"found\":{found},\"syn\":{{\"sent\":{count},\"total\":{max_count},\"remaining\":{}}}}}}}\n",
        pps / 1000.0,
        max_count.saturating_sub(count)
    )
}

/// Текст строки stderr после последнего `\r`: то, что остаётся на терминале. Тесты и лаборатория сравнивают строки
/// `[+] …`, перед которыми стоят фрагменты статуса.
pub fn normalize_stderr_line(line: &str) -> &str {
    line.rsplit('\r').next().unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(l: &mut StatusLine, now: u64, count: u64, pps: f64, exiting: Option<i64>) -> String {
        let mut b = Vec::new();
        l.tick(now, count, 1000, pps, 3, exiting, &mut b).unwrap();
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn running_line_matches_c() {
        assert_eq!(
            running_line(0.1, 12.5, 3725.0, 3),
            "rate:  0.10-kpps, 12.50% done,   1:02:05 remaining, found=3       \r"
        );
    }

    #[test]
    fn waiting_line_matches_c() {
        assert_eq!(
            waiting_line(0.0, 100.0, 7, 8),
            "rate:  0.00-kpps, 100.00% done, waiting 7-secs, found=8       \r"
        );
    }

    #[test]
    fn ndjson_lines_match_c() {
        assert_eq!(
            ndjson_running(100.0, 12.5, 3725.0, 3, 25, 200),
            "{\"state\":\"running\",\"rate\":{\"kpps\":0.10,\"pps\":100.00},\"progress\":{\"percent\":12.50,\"eta\":{\"hours\":1,\"mins\":2,\"seconds\":5},\"syn\":{\"sent\":25,\"total\":200,\"remaining\":175},\"found\":3}}\n"
        );
        assert_eq!(
            ndjson_waiting(0.0, 100.0, 7, 8, 200, 200),
            "{\"state\":\"waiting\",\"rate\":{\"kpps\":0.00,\"pps\":0.00},\"progress\":{\"percent\":100.00,\"seconds\":7,\"found\":8,\"syn\":{\"sent\":200,\"total\":200,\"remaining\":0}}}\n"
        );
    }

    #[test]
    fn degenerate_inputs_never_print_nan_or_inf() {
        assert_eq!(
            running_line(0.0, 0.0, f64::INFINITY, 0),
            "rate:  0.00-kpps,  0.00% done,   0:00:00 remaining, found=0       \r"
        );
        let mut l = StatusLine::new(StatusMode::Text, 0);
        let s = run(&mut l, 1_000_000, 0, 0.0, None);
        assert!(s.contains("0:00:00 remaining"), "{s}");
        let mut l = StatusLine::new(StatusMode::Text, 0);
        let mut b = Vec::new();
        l.tick(1_000_000, 0, 0, 0.0, 0, None, &mut b).unwrap();
        let s = String::from_utf8(b).unwrap();
        assert!(!s.contains("NaN") && !s.contains("inf"), "{s}");
    }

    #[test]
    fn tick_cadence() {
        let mut l = StatusLine::new(StatusMode::Text, 0);
        // elapsed <= 0: ничего.
        assert_eq!(run(&mut l, 0, 10, 100.0, None), "");
        assert!(run(&mut l, 250_000, 10, 100.0, None).starts_with("rate:"));
        // передача: не чаще 750 мс
        assert_eq!(run(&mut l, 500_000, 20, 100.0, None), "");
        assert_eq!(run(&mut l, 999_999, 20, 100.0, None), "");
        assert!(run(&mut l, 1_000_000, 20, 100.0, None).starts_with("rate:"));
        // ожидание: 250 мс
        assert_eq!(run(&mut l, 1_100_000, 1000, 0.0, Some(5)), "");
        assert!(run(&mut l, 1_250_000, 1000, 0.0, Some(5)).contains("waiting 5-secs"),);
        assert!(run(&mut l, 1_500_000, 1000, 0.0, Some(4)).contains("waiting 4-secs"));
    }

    #[test]
    fn remaining_time_uses_average_of_last_eight_samples() {
        // Первый отсчёт: 100 за 1 с = 100/с; среднее по 8 слотам (7 нулей) = 12.5/с.
        // percent = 10, осталось (1 - 0.1) * (1000 / 12.5) = 72 с; kpps печатается мгновенный: 5000/1000.
        let mut l = StatusLine::new(StatusMode::Text, 0);
        let s = run(&mut l, 1_000_000, 100, 5000.0, None);
        assert_eq!(
            s,
            "rate:  5.00-kpps, 10.00% done,   0:01:12 remaining, found=3       \r"
        );
    }

    #[test]
    fn finish_blanks_the_line() {
        let mut b = Vec::new();
        StatusLine::new(StatusMode::Text, 0).finish(&mut b).unwrap();
        assert_eq!(b, [b" ".repeat(77), b"\r".to_vec()].concat());
        let mut b = Vec::new();
        StatusLine::new(StatusMode::Off, 0).finish(&mut b).unwrap();
        assert!(b.is_empty());
        let mut l = StatusLine::new(StatusMode::Off, 0);
        assert_eq!(run(&mut l, 5_000_000, 5, 1.0, None), "");
    }

    #[test]
    fn normalize_keeps_text_after_last_cr() {
        assert_eq!(normalize_stderr_line("a\rb\r[+] finished"), "[+] finished");
        assert_eq!(normalize_stderr_line("[+] x"), "[+] x");
    }
}
