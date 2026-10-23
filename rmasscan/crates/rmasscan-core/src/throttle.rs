//! Троттлер скорости отправки (AGPL-3.0). Порт `src/main-throttle.c` из
//! masscan © Robert David Graham (github.com/robertdavidgraham/masscan,
//! HEAD 8e6b3b0).
//!
//! Арифметика повторяет C: `double` для скоростей и `batch_size`, `uint64_t`
//! для корзин (с оборачиванием при вычитании), тот же порядок вызовов часов и
//! сна, та же структура цикла (`goto again` -> `loop`/`continue`).

use std::time::{Duration, Instant};

/// Максимальный отрезок сна внутри [`Throttler::next_batch_interruptible`]:
/// между отрезками проверяется флаг отмены (требование runtime: Stop/Pause
/// обрабатываются за доли секунды даже на rate=1).
pub const MAX_SLEEP_CHUNK_MICROS: u64 = 50_000;

/// Ожидание throttle прервано флагом отмены.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("throttle wait cancelled")]
pub struct ThrottleCancelled;

/// Источник времени и сна. Подменяется в тестах.
pub trait Clock {
    /// Монотонное время в МИКРОСЕКУНДАХ (как `pixie_gettime()`,
    /// pixie-timer.c:187-205: `tv_sec*1000000 + tv_nsec/1000`).
    fn now_micros(&self) -> u64;

    /// Сон на `us` микросекунд (`pixie_usleep`, pixie-timer.c:168). В проде
    /// спит, в тестовых часах продвигает время ровно на `us`.
    fn sleep_micros(&self, us: u64);
}

/// Боевые часы поверх `std::time::Instant` (монотонные, без учёта
/// приостановки не гарантируют, как CLOCK_UPTIME_RAW на macOS, но не идут назад).
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_micros(&self) -> u64 {
        self.origin.elapsed().as_micros() as u64
    }

    fn sleep_micros(&self, us: u64) {
        std::thread::sleep(Duration::from_micros(us));
    }
}

/// `struct Throttler`, main-throttle.h:5.
#[derive(Debug, Clone)]
pub struct Throttler {
    /// (timestamp, packet_count), main-throttle.h:13.
    buckets: [(u64, u64); 256],
    /// `unsigned index` в C: оборачивается по 2^32, маска 0xFF не меняется.
    index: u32,
    batch_size: f64,
    max_rate: f64,
    current_rate: f64,
}

impl Throttler {
    /// `throttler_start`, main-throttle.c:28: все корзины = now, batch_size = 1.
    pub fn start(max_rate: f64, clock: &(impl Clock + ?Sized)) -> Self {
        let mut buckets = [(0u64, 0u64); 256];
        for b in buckets.iter_mut() {
            *b = (clock.now_micros(), 0);
        }
        Self {
            buckets,
            index: 0,
            batch_size: 1.0,
            max_rate,
            current_rate: 0.0,
        }
    }

    pub fn max_rate(&self) -> f64 {
        self.max_rate
    }

    pub fn current_rate(&self) -> f64 {
        self.current_rate
    }

    pub fn batch_size(&self) -> f64 {
        self.batch_size
    }

    /// `throttler_next_batch`, main-throttle.c:58. `packet_count` — общее
    /// число отправленных пакетов (накопительное). Возвращает размер пачки;
    /// как в C это `(uint64_t)batch_size`, поэтому при batch_size < 1 вернётся 0
    /// (приведение double -> uint64 усекает к нулю).
    ///
    /// Совместимая обёртка над [`Self::next_batch_interruptible`] без отмены и
    /// без дробления сна: последовательность вызовов часов и сна такая же, как
    /// в C (stage-1 golden и benchmark не меняются).
    ///
    /// Контракт вызывающего: один `Throttler` на TX-поток, запущенный с
    /// плановой скоростью; `start` и `next_batch` получают одни и те же часы;
    /// результат 0 означает "вызвать снова".
    pub fn next_batch(&mut self, packet_count: u64, clock: &(impl Clock + ?Sized)) -> u64 {
        self.next_batch_impl(packet_count, clock, &|| false, u64::MAX)
            .unwrap_or(0)
    }

    /// То же, что [`Self::next_batch`], но отменяемо: `cancelled` проверяется
    /// в начале каждого повтора цикла, до и после каждого сна, а длинный сон
    /// режется на отрезки не длиннее [`MAX_SLEEP_CHUNK_MICROS`]. Проверки
    /// только снаружи `next_batch` недостаточны (один вызов может спать
    /// секунды на малой скорости).
    pub fn next_batch_interruptible(
        &mut self,
        packet_count: u64,
        clock: &(impl Clock + ?Sized),
        cancelled: impl Fn() -> bool,
    ) -> Result<u64, ThrottleCancelled> {
        self.next_batch_impl(packet_count, clock, &cancelled, MAX_SLEEP_CHUNK_MICROS)
    }

    fn next_batch_impl(
        &mut self,
        packet_count: u64,
        clock: &(impl Clock + ?Sized),
        cancelled: &dyn Fn() -> bool,
        chunk: u64,
    ) -> Result<u64, ThrottleCancelled> {
        let max_rate = self.max_rate;
        loop {
            if cancelled() {
                return Err(ThrottleCancelled);
            }
            // :69
            let timestamp = clock.now_micros();

            // :76-78
            let mut index = (self.index & 0xFF) as usize;
            self.buckets[index] = (timestamp, packet_count);

            // :80-82
            self.index = self.index.wrapping_add(1);
            index = (self.index & 0xFF) as usize;
            let (old_timestamp, old_packet_count) = self.buckets[index];

            // :88-92 разрыв > 1 с: сброс batch_size и повтор (без сна).
            if timestamp.wrapping_sub(old_timestamp) > 1_000_000 {
                self.batch_size = 1.0;
                continue;
            }

            // :99. Деление на ноль даёт inf/NaN как в C (IEEE); NaN > max_rate
            // ложно, как и в C.
            let current_rate = 1.0 * (packet_count.wrapping_sub(old_packet_count) as f64)
                / (timestamp.wrapping_sub(old_timestamp) as f64 / 1_000_000.0);

            // :106-147
            if current_rate > max_rate {
                let mut waittime = (current_rate - self.max_rate) / self.max_rate;
                waittime *= 0.1;
                if waittime > 0.1 {
                    waittime = 0.1;
                }
                self.batch_size *= 0.999;
                let mut remaining = (waittime * 1_000_000.0) as u64;
                loop {
                    // Отмена, обнаруженная прямо перед сном, не начинает новый сон.
                    if cancelled() {
                        return Err(ThrottleCancelled);
                    }
                    let part = remaining.min(chunk);
                    clock.sleep_micros(part);
                    remaining -= part;
                    if cancelled() {
                        return Err(ThrottleCancelled);
                    }
                    if remaining == 0 {
                        break;
                    }
                }
                continue;
            }

            // :155-162
            self.batch_size *= 1.005;
            if self.batch_size > 10000.0 {
                self.batch_size = 10000.0;
            }
            self.current_rate = current_rate;
            return Ok(self.batch_size as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Фиктивные часы: сон продвигает время ровно на `us`; `tick` добавляется
    /// после каждого чтения (имитация того, что реальное время идёт).
    struct FakeClock {
        now: Cell<u64>,
        tick: u64,
        sleeps: Cell<u64>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self::with_tick(0)
        }
        fn with_tick(tick: u64) -> Self {
            Self {
                now: Cell::new(1_000_000),
                tick,
                sleeps: Cell::new(0),
            }
        }
        fn advance_micros(&self, us: u64) {
            self.now.set(self.now.get() + us);
        }
    }

    impl Clock for FakeClock {
        fn now_micros(&self) -> u64 {
            let t = self.now.get();
            self.now.set(t + self.tick);
            t
        }
        fn sleep_micros(&self, us: u64) {
            self.sleeps.set(self.sleeps.get() + 1);
            self.now.set(self.now.get() + us);
        }
    }

    #[test]
    fn batch_size_is_one_at_low_rate() {
        let c = FakeClock::new();
        let mut t = Throttler::start(100.0, &c);
        c.advance_micros(10_000); // 10 мс
        assert_eq!(t.next_batch(1, &c), 1);
    }

    #[test]
    fn gap_over_one_second_resets_batch_to_one() {
        // main-throttle.c:90: timestamp - old > 1_000_000 -> batch_size = 1.
        let c = FakeClock::new();
        let mut t = Throttler::start(1_000_000.0, &c);
        c.advance_micros(2_000_000);
        // Сброс в 1, затем повтор: корзины теперь свежие (sleep не нужен).
        t.batch_size = 500.0;
        let r = t.next_batch(5_000_000, &c);
        assert_eq!(r, 1);
        assert_eq!(c.sleeps.get(), 0);
    }

    #[test]
    fn batch_size_grows_under_high_rate() {
        // 2 Mpps при лимите 5 Mpps: 1 пакет за 0.5 мкс -> по 2 пакета/мкс.
        let c = FakeClock::new();
        let mut t = Throttler::start(5_000_000.0, &c);
        let mut pc = 0u64;
        let mut max_seen = 0;
        for _ in 0..5000 {
            c.advance_micros(1);
            pc += 2;
            let b = t.next_batch(pc, &c);
            assert!((1..=10000).contains(&b));
            max_seen = max_seen.max(b);
        }
        assert!(max_seen > 1, "batch_size must grow, max {max_seen}");
    }

    #[test]
    fn batch_size_is_capped_at_10000() {
        let c = FakeClock::new();
        let mut t = Throttler::start(1e12, &c);
        let mut pc = 0;
        for _ in 0..5000 {
            c.advance_micros(1);
            pc += 1;
            t.next_batch(pc, &c);
        }
        assert_eq!(t.batch_size(), 10000.0);
        assert_eq!(t.next_batch(pc + 1, &c), 10000);
    }

    #[test]
    fn over_rate_sleeps_with_capped_wait_and_shrinks_batch() {
        // 1000 пакетов за ~10 мкс при лимите 20000 pps: waittime капится
        // 0.1 с (:131); после одного сна скорость ~10000 pps <= лимита.
        let c = FakeClock::with_tick(1);
        let mut t = Throttler::start(20_000.0, &c);
        t.batch_size = 100.0;
        c.advance_micros(10);
        let r = t.next_batch(1000, &c);
        assert_eq!(c.sleeps.get(), 1);
        assert!(c.now.get() >= 1_000_000 + 100_000);
        // 0.999 на сне (:145), затем 1.005 (:155).
        let expect = 100.0 * 0.999 * 1.005;
        assert!((t.batch_size() - expect).abs() < 1e-9);
        assert_eq!(r, 100);
    }

    #[test]
    fn batch_below_one_truncates_to_zero_like_c() {
        // (uint64_t)0.5 == 0 в C: возврат 0 при batch_size < 1.
        let c = FakeClock::new();
        let mut t = Throttler::start(100.0, &c);
        t.batch_size = 0.1;
        c.advance_micros(10_000);
        assert_eq!(t.next_batch(1, &c), 0);
    }

    #[test]
    fn index_wraps_over_256_buckets() {
        let c = FakeClock::new();
        let mut t = Throttler::start(1e9, &c);
        for i in 1..=600u64 {
            c.advance_micros(100);
            t.next_batch(i, &c);
        }
        assert_eq!(t.index, 600);
    }

    #[test]
    fn system_clock_is_monotonic_micros() {
        let c = SystemClock::new();
        let a = c.now_micros();
        c.sleep_micros(2000);
        assert!(c.now_micros() >= a + 2000);
    }

    // ---- отмена внутри throttle ----

    #[test]
    fn cancelled_before_any_clock_read_returns_err() {
        let c = FakeClock::new();
        let mut t = Throttler::start(100.0, &c);
        let before = c.now.get();
        assert_eq!(
            t.next_batch_interruptible(0, &c, || true),
            Err(ThrottleCancelled)
        );
        assert_eq!(c.now.get(), before);
        assert_eq!(c.sleeps.get(), 0);
    }

    #[test]
    fn interruptible_without_cancel_matches_next_batch() {
        let a = FakeClock::with_tick(1);
        let b = FakeClock::with_tick(1);
        let mut ta = Throttler::start(20_000.0, &a);
        let mut tb = Throttler::start(20_000.0, &b);
        let mut pc = 0;
        for _ in 0..200 {
            a.advance_micros(7);
            b.advance_micros(7);
            pc += 3;
            let x = ta.next_batch(pc, &a);
            let y = tb.next_batch_interruptible(pc, &b, || false).unwrap();
            assert_eq!(x, y);
            assert_eq!(ta.current_rate().to_bits(), tb.current_rate().to_bits());
        }
    }

    #[test]
    fn long_sleep_is_split_into_chunks_of_at_most_50ms() {
        // Тот же сценарий, что over_rate_sleeps_with_capped_wait: один сон в
        // 100 мс. Обёртка спит одним вызовом, интерруптибл: двумя по 50 мс.
        let c = FakeClock::with_tick(1);
        let mut t = Throttler::start(20_000.0, &c);
        t.batch_size = 100.0;
        c.advance_micros(10);
        let r = t.next_batch_interruptible(1000, &c, || false).unwrap();
        assert_eq!(c.sleeps.get(), 2);
        assert!(c.now.get() >= 1_000_000 + 100_000);
        assert_eq!(r, 100);
    }

    #[test]
    fn cancel_during_long_sleep_stops_after_one_chunk() {
        let c = FakeClock::with_tick(1);
        let mut t = Throttler::start(1.0, &c); // rate=1: сон капится 100 мс
        c.advance_micros(10);
        let sleeps = &c.sleeps;
        let res = t.next_batch_interruptible(1000, &c, || sleeps.get() >= 1);
        assert_eq!(res, Err(ThrottleCancelled));
        // Один отрезок <= 50 мс, а не весь сон и не повтор цикла.
        assert_eq!(c.sleeps.get(), 1);
        assert!(c.now.get() < 1_000_000 + 60_000);
    }

    #[test]
    fn cancel_is_checked_inside_the_retry_loop_without_sleeps() {
        // Часы прыгают на 2 с при каждом чтении: ветка ":88 разрыв > 1 с" ->
        // `continue` повторяется бесконечно, сна нет. Отмена обязана её прервать.
        let c = FakeClock::with_tick(2_000_000);
        let mut t = Throttler::start(100.0, &c);
        let checks = Cell::new(0u32);
        let res = t.next_batch_interruptible(1, &c, || {
            checks.set(checks.get() + 1);
            checks.get() > 5
        });
        assert_eq!(res, Err(ThrottleCancelled));
        assert_eq!(c.sleeps.get(), 0);
    }

    #[test]
    fn cancel_detected_right_before_a_sleep_starts_no_new_sleep() {
        let c = FakeClock::with_tick(1);
        let mut t = Throttler::start(1.0, &c); // rate=1: требуется сон
        c.advance_micros(10);
        let checks = Cell::new(0u32);
        // 1-я проверка (верх цикла) пуста; 2-я, прямо перед сном, срабатывает.
        let res = t.next_batch_interruptible(1000, &c, || {
            checks.set(checks.get() + 1);
            checks.get() >= 2
        });
        assert_eq!(res, Err(ThrottleCancelled));
        assert_eq!(c.sleeps.get(), 0, "a sleep started after cancellation");
    }

    #[test]
    fn cancel_after_sleep_is_noticed_before_next_clock_read() {
        let c = FakeClock::with_tick(1);
        let mut t = Throttler::start(20_000.0, &c);
        t.batch_size = 100.0;
        c.advance_micros(10);
        let flag = Cell::new(false);
        // Отмена выставляется внутри сна (после первого отрезка).
        struct Hook<'a>(&'a FakeClock, &'a Cell<bool>);
        impl Clock for Hook<'_> {
            fn now_micros(&self) -> u64 {
                self.0.now_micros()
            }
            fn sleep_micros(&self, us: u64) {
                self.0.sleep_micros(us);
                self.1.set(true);
            }
        }
        let h = Hook(&c, &flag);
        let res = t.next_batch_interruptible(1000, &h, || flag.get());
        assert_eq!(res, Err(ThrottleCancelled));
        assert_eq!(c.sleeps.get(), 1);
    }
}
