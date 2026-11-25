//! Списки диапазонов IPv4-адресов и портов (AGPL-3.0).
//! Порт `src/massip-rangesv4.c` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Список используется и для адресов (u32), и для портов (0..=65535 плюс
//! смещения протоколов), поэтому, как и в C, всё хранится как `u32`.

/// Двоичный поиск значения в диапазонах, отсортированных по началу и не пересекающихся: O(log n). Общий для IPv4,
/// портов и IPv6 (`bounds` отдаёт `(begin, end)` элемента).
pub(crate) fn contains_sorted<R, V: Ord + Copy>(
    ranges: &[R],
    value: V,
    bounds: impl Fn(&R) -> (V, V),
) -> bool {
    let idx = ranges.partition_point(|r| bounds(r).0 <= value);
    idx.checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|r| value <= bounds(r).1)
}

/// Инклюзивный диапазон `[begin, end]`. `begin > end` означает «пустой».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub begin: u32,
    pub end: u32,
}

/// Невалидный диапазон (massip-rangesv4.c:51 `INVALID_RANGE = {2,1}`).
const INVALID_RANGE: Range = Range { begin: 2, end: 1 };

impl Range {
    /// massip-rangesv4.c:719 `range_is_valid`.
    fn is_valid(self) -> bool {
        self.begin <= self.end
    }

    /// massip-rangesv4.c:189 `range_is_overlap` (включая смежные диапазоны).
    /// `end + 1` на границе 0xFFFFFFFF считается в u64 (в C защищено
    /// проверкой `== 0xFFFFFFFF`).
    fn is_overlap(lhs: Range, rhs: Range) -> bool {
        let succ = |v: u32| u64::from(v) + 1;
        if lhs.begin < rhs.begin && (lhs.end == u32::MAX || succ(lhs.end) >= u64::from(rhs.begin)) {
            return true;
        }
        if lhs.begin >= rhs.begin && lhs.end <= rhs.end {
            return true;
        }
        if rhs.begin < lhs.begin && (rhs.end == u32::MAX || succ(rhs.end) >= u64::from(lhs.begin)) {
            return true;
        }
        if rhs.begin >= lhs.begin && rhs.end <= lhs.end {
            return true;
        }
        false
    }

    /// massip-rangesv4.c:217 `range_combine`.
    fn combine(&mut self, rhs: Range) {
        self.begin = self.begin.min(rhs.begin);
        self.end = self.end.max(rhs.end);
    }

    /// massip-rangesv4.c:674 `range_apply_exclude`. Возвращает `split`
    /// (INVALID_RANGE, если разбиения нет); `self` меняется на месте.
    fn apply_exclude(&mut self, exclude: Range) -> Range {
        // Case 1: нет пересечения
        if self.begin > exclude.end || self.end < exclude.begin {
            return INVALID_RANGE;
        }
        // Case 2: полностью исключён
        if self.begin >= exclude.begin && self.end <= exclude.end {
            *self = INVALID_RANGE;
            return INVALID_RANGE;
        }
        // Case 3: пересечение в начале
        if self.begin >= exclude.begin && self.end > exclude.end {
            self.begin = exclude.end.wrapping_add(1);
            return INVALID_RANGE;
        }
        // Case 4: пересечение в конце
        if self.begin < exclude.begin && self.end <= exclude.end {
            self.end = exclude.begin.wrapping_sub(1);
            return INVALID_RANGE;
        }
        // Case 5: разбиение на два
        debug_assert!(self.begin < exclude.begin && self.end > exclude.end);
        let split = Range {
            begin: exclude.end.wrapping_add(1),
            end: self.end,
        };
        self.end = exclude.begin.wrapping_sub(1);
        split
    }
}

/// Отсортированный, слитый список диапазонов + префиксные суммы `picker`
/// (massip-rangesv4.h `struct RangeList`).
#[derive(Debug, Clone)]
pub struct RangeList {
    list: Vec<Range>,
    /// Префиксные суммы размеров; строится `optimize`. Как в C, `u32`.
    picker: Option<Vec<u32>>,
    is_sorted: bool,
}

impl Default for RangeList {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeList {
    pub fn new() -> Self {
        // Пустой список отсортирован (massip-rangesv4.c:269).
        Self {
            list: Vec::new(),
            picker: None,
            is_sorted: true,
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn get(&self, index: usize) -> Range {
        self.list[index]
    }

    pub fn as_slice(&self) -> &[Range] {
        &self.list
    }

    /// massip-rangesv4.c:310 `rangelist_add_range`: если новый диапазон
    /// пересекает последний в списке, он сливается с ним, иначе
    /// добавляется в конец. Отличие от C: устаревший `picker` сбрасывается.
    pub fn add_range(&mut self, begin: u32, end: u32) {
        let range = Range { begin, end };
        self.picker = None;
        let Some(last) = self.list.last_mut() else {
            self.list.push(range);
            self.is_sorted = true;
            return;
        };
        if Range::is_overlap(*last, range) {
            last.combine(range);
        } else {
            self.list.push(range);
        }
        self.is_sorted = false;
    }

    /// massip-rangesv4.c:258 `rangelist_sort`: сортировка по `begin` и
    /// слияние перекрытий через повторный `add_range`.
    pub fn sort_and_merge(&mut self) {
        if self.list.is_empty() {
            self.is_sorted = true;
            return;
        }
        if self.is_sorted {
            return;
        }
        self.list.sort_by_key(|r| r.begin);
        let old = std::mem::take(&mut self.list);
        for r in old {
            self.add_range(r.begin, r.end);
        }
        self.picker = None;
        self.is_sorted = true;
    }

    /// massip-rangesv4.c:60 `rangelist_is_contains` (в C всегда линейный поиск).
    /// Здесь отсортированный список (`sort_and_merge`, `optimize`, `exclude`) ищется двоичным поиском, иначе линейно.
    pub fn is_contains(&self, value: u32) -> bool {
        if self.is_sorted {
            return contains_sorted(&self.list, value, |r| (r.begin, r.end));
        }
        self.list.iter().any(|r| r.begin <= value && value <= r.end)
    }

    /// massip-rangesv4.c:798 `rangelist_count`; для 0.0.0.0/0 это 0x1_0000_0000.
    pub fn count(&self) -> u64 {
        self.list
            .iter()
            .map(|r| {
                u64::from(r.end)
                    .wrapping_sub(u64::from(r.begin))
                    .wrapping_add(1)
            })
            .fold(0, u64::wrapping_add)
    }

    /// massip-rangesv4.c:884 `rangelist_optimize`: префиксные суммы для
    /// бинарного поиска в `pick`. `total` — `u32` с оборачиванием, как в C.
    pub fn optimize(&mut self) {
        if self.list.is_empty() {
            return;
        }
        self.sort_and_merge();
        let mut total: u32 = 0;
        let picker = self
            .list
            .iter()
            .map(|r| {
                let p = total;
                total = total.wrapping_add(r.end.wrapping_sub(r.begin).wrapping_add(1));
                p
            })
            .collect();
        self.picker = Some(picker);
    }

    /// massip-rangesv4.c:820 `rangelist_pick_linearsearch`.
    fn pick_linear(&self, mut index: u64) -> u32 {
        for r in &self.list {
            let size = u64::from(r.end)
                .wrapping_sub(u64::from(r.begin))
                .wrapping_add(1);
            if index < size {
                return r.begin.wrapping_add(index as u32);
            }
            index = index.wrapping_sub(size);
        }
        panic!("rangelist pick: index out of range (C: assert \"end of list\")");
    }

    /// massip-rangesv4.c:839 `rangelist_pick`: `index`-й адрес/порт списка.
    /// Список должен быть отсортирован (в C `pick` сортирует сам; здесь
    /// `&self`, поэтому это утверждение).
    pub fn pick(&self, index: u64) -> u32 {
        assert!(self.is_sorted, "pick requires a sorted RangeList");
        let Some(picker) = self.picker.as_deref() else {
            return self.pick_linear(index);
        };
        let maxmax = self.list.len();
        let (mut min, mut max) = (0usize, maxmax);
        let mid = loop {
            let mid = min + (max - min) / 2;
            if index < u64::from(picker[mid]) {
                max = mid;
                continue;
            }
            if mid + 1 == maxmax || index < u64::from(picker[mid + 1]) {
                break mid;
            }
            min = mid + 1;
        };
        self.list[mid]
            .begin
            .wrapping_add((index - u64::from(picker[mid])) as u32)
    }

    /// massip-rangesv4.c:730 `rangelist_exclude`: вычитает `excludes` из
    /// списка; обе стороны сортируются; диапазон может разбиться на два.
    pub fn exclude(&mut self, excludes: &mut RangeList) {
        self.sort_and_merge();
        excludes.sort_and_merge();

        let mut newlist = RangeList::new();
        let mut x = 0usize;
        for mut range in self.list.iter().copied() {
            // Двигаем exclude вперёд до возможного пересечения
            while x < excludes.list.len() && excludes.list[x].end < range.begin {
                x += 1;
            }
            // Применяем excludes, пока есть пересечения
            while x < excludes.list.len() && excludes.list[x].begin <= range.end {
                let split = range.apply_exclude(excludes.list[x]);
                if split.is_valid() {
                    newlist.add_range(range.begin, range.end);
                    range = split;
                }
                // Если текущая цель снята целиком (`!range.is_valid()`) или исключение
                // обрезало хвост (`begin > range.end`), не двигаем `x`: то же исключение
                // может накрывать и следующие цели. В C (`massip-rangesv4.c:766`) при
                // `INVALID_RANGE {2, 1}` проверялось только `begin > 1`, из-за чего
                // исключение с `begin` 0 или 1 пропускалось для следующих целей (баг B1).
                if !range.is_valid() || excludes.list[x].begin > range.end {
                    break;
                }
                x += 1;
            }
            if range.is_valid() {
                newlist.add_range(range.begin, range.end);
            }
        }

        self.list = newlist.list;
        self.picker = None;
        // C :787 rangelist_sort is a no-op here: is_sorted stays 1 from :738.
        self.is_sorted = true;
    }
}

/// `Some(prefix_bits)` если диапазон ровно один CIDR-блок (`0..=32`).
///
/// Исправляет UB в C (`massip-rangesv4.c:98-101`, баг B2), где при `begin == 0`
/// сдвиг `0xFFFFFFFF << 33` давал `0.0.0.0/4294967295` для `0.0.0.0/31` и
/// печатал `0.0.0.0/8`, `0.0.0.0/4` через дефис.
pub fn range_is_cidr(range: Range) -> Option<u32> {
    let span = range.end.checked_sub(range.begin)?;
    if span == u32::MAX {
        return Some(0);
    }
    let len = span + 1;
    if len.is_power_of_two() && (range.begin & span) == 0 {
        Some(32 - span.trailing_ones())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn range_is_cidr_cases() {
        // Таблица selftest_range_first_cidr (massip-rangesv4.c:136-150),
        // пересчитанная на "диапазон целиком CIDR?".
        assert_eq!(range_is_cidr(r(0, u32::MAX)), Some(0));
        assert_eq!(range_is_cidr(r(1, u32::MAX)), None);
        assert_eq!(range_is_cidr(r(u32::MAX, u32::MAX)), Some(32));
        assert_eq!(range_is_cidr(r(0x0A00_0000, 0x0A00_00FF)), Some(24));
        assert_eq!(range_is_cidr(r(0x0A00_0001, 0x0A00_00FE)), None);
        assert_eq!(range_is_cidr(r(0x0A00_0008, 0x0A00_000F)), Some(29));
        assert_eq!(range_is_cidr(r(0x0A00_0008, 0x0A00_00FE)), None);
        assert_eq!(range_is_cidr(r(0x0A00_0000, 0x0A00_007F)), Some(25));
        // Не выровнен по размеру: 10.0.0.128-10.0.1.127 не CIDR.
        assert_eq!(range_is_cidr(r(0x0A00_0080, 0x0A00_017F)), None);
        // begin == 0: исправление бага B2 (в C был UB сдвига `0xFFFFFFFF << 33`).
        assert_eq!(range_is_cidr(r(0, 0x00FF_FFFF)), Some(8)); // 0.0.0.0/8
        assert_eq!(range_is_cidr(r(0, 0x0FFF_FFFF)), Some(4)); // 0.0.0.0/4
        assert_eq!(range_is_cidr(r(0, 0x7FFF_FFFF)), Some(1)); // 0.0.0.0/1
        assert_eq!(range_is_cidr(r(0, 1)), Some(31)); // 0.0.0.0/31
        assert_eq!(range_is_cidr(r(0, 2)), None);
        assert_eq!(range_is_cidr(r(0, 0)), Some(32)); // 0.0.0.0/32
    }

    const fn r(begin: u32, end: u32) -> Range {
        Range { begin, end }
    }

    /// massip-rangesv4.c:919 `r_rand` (LCG a=214013, c=2531011).
    fn r_rand(seed: &mut u32) -> u32 {
        *seed = seed.wrapping_mul(214013).wrapping_add(2531011);
        (*seed >> 16) & 0x7fff
    }

    /// massip-rangesv4.c:1098 `lcgrand`.
    fn lcgrand(state: &mut u32) -> u32 {
        *state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *state
    }

    /// Устаревший `rangelist_remove_range` (massip-rangesv4.c:401), эталон
    /// для `exclude_selftest`. Арифметика `end+1`/`begin-1` с оборачиванием.
    fn remove_range(t: &mut RangeList, begin: u32, end: u32) {
        let x = r(begin, end);
        let mut i: usize = 0;
        while i < t.list.len() {
            let cur = t.list[i];
            if !Range::is_overlap(cur, x) {
                i += 1;
                continue;
            }
            if begin <= cur.begin && end >= cur.end {
                t.list.remove(i);
                continue;
            }
            if begin > cur.begin && end < cur.end {
                let (nb, ne) = (end.wrapping_add(1), cur.end);
                t.list[i].end = begin.wrapping_sub(1);
                t.add_range(nb, ne);
                // C: i-- затем i++ из цикла for, то есть тот же индекс.
                continue;
            }
            let cur = &mut t.list[i];
            if end >= cur.begin && end < cur.end {
                cur.begin = end.wrapping_add(1);
            }
            if begin > cur.begin && begin <= cur.end {
                cur.end = begin.wrapping_sub(1);
            }
            i += 1;
        }
    }

    /// `rangelist_exclude2` (massip-rangesv4.c:645).
    fn exclude2(t: &mut RangeList, ex: &RangeList) {
        for e in &ex.list {
            remove_range(t, e.begin, e.end);
        }
        t.sort_and_merge();
    }

    fn list(ranges: &[(u32, u32)]) -> RangeList {
        let mut l = RangeList::new();
        for &(b, e) in ranges {
            l.add_range(b, e);
        }
        l
    }

    /// Копия линейного `is_contains` базы: эталон для двоичного поиска.
    fn linear_contains(l: &RangeList, v: u32) -> bool {
        l.list.iter().any(|r| r.begin <= v && v <= r.end)
    }

    fn value() -> impl Strategy<Value = u32> {
        prop_oneof![0u32..40, (u32::MAX - 40)..=u32::MAX, any::<u32>(),]
    }

    fn pairs() -> impl Strategy<Value = Vec<(u32, u32)>> {
        // `begin > end` возможен: оба конца берутся независимо.
        proptest::collection::vec((value(), value()), 0..12)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3000))]

        #[test]
        fn is_contains_binary_equals_linear(
            adds in pairs(),
            excl in pairs(),
            mode in 0u8..4,
            extra in proptest::collection::vec(value(), 64),
        ) {
            let mut l = list(&adds);
            match mode {
                0 => {}
                1 => l.sort_and_merge(),
                2 => {
                    let mut e = list(&excl);
                    l.exclude(&mut e);
                }
                _ => {
                    // исключение от 0.0.0.0
                    let mut e = list(&excl);
                    let hi = excl.first().map_or(7, |p| p.1);
                    e.add_range(0, hi);
                    l.exclude(&mut e);
                }
            }
            let mut probes = extra;
            for r in l.as_slice() {
                for v in [r.begin, r.end] {
                    probes.extend([v, v.saturating_sub(1), v.saturating_add(1)]);
                }
            }
            for &(b, e) in adds.iter().chain(excl.iter()) {
                probes.extend([b, e]);
            }
            for v in probes {
                let want = linear_contains(&l, v);
                prop_assert_eq!(l.is_contains(v), want, "is_contains {} sorted {}", v, l.is_sorted);
                if l.is_sorted {
                    prop_assert_eq!(
                        contains_sorted(l.as_slice(), v, |r| (r.begin, r.end)),
                        want,
                        "sorted {}", v
                    );
                }
            }
        }
    }

    #[test]
    fn sort_merges_overlapping_ipv4() {
        // ranges_selftest :1287-1298
        let mut t = list(&[
            (0x0a00_0000, 0x0a00_00ff), // 10.0.0.0/24
            (0x0a00_010a, 0x0a00_0113), // 10.0.1.10-10.0.1.19
            (0x0a00_0114, 0x0a00_011e), // 10.0.1.20-10.0.1.30
            (0x0a00_0000, 0x0a00_010c), // 10.0.0.0-10.0.1.12
        ]);
        t.sort_and_merge();
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(0), r(0x0a00_0000, 0x0a00_0100 + 30));
    }

    #[test]
    fn pick_reproduces_sorted_list() {
        // regress_pick2 :931
        let mut seed = 0u32;
        for _ in 0..100 {
            let mut targets = RangeList::new();
            let mut begin = 0u32;
            let num_targets = r_rand(&mut seed) % 5 + 1;
            for _ in 0..num_targets {
                begin += r_rand(&mut seed) % 10;
                let end = begin + r_rand(&mut seed) % 10;
                targets.add_range(begin, end);
            }
            targets.sort_and_merge();
            let range = targets.count();
            targets.optimize();

            let mut dup = RangeList::new();
            for j in 0..range {
                let x = targets.pick(j);
                dup.add_range(x, x);
            }
            dup.sort_and_merge();
            assert_eq!(targets.as_slice(), dup.as_slice());

            // Линейный fallback даёт то же самое.
            let mut plain = targets.clone();
            plain.picker = None;
            for j in 0..range {
                assert_eq!(plain.pick(j), targets.pick(j));
            }
        }
    }

    fn fill_lcg(seed_init: u32) -> RangeList {
        let mut seed = seed_init;
        let mut addr = 0u32;
        let mut l = RangeList::new();
        for _ in 0..1000 {
            addr = addr.wrapping_add(lcgrand(&mut seed) & 0xF);
            let begin = addr;
            addr = addr.wrapping_add(lcgrand(&mut seed) & 0xF);
            l.add_range(begin, addr);
        }
        l.sort_and_merge();
        l
    }

    #[test]
    fn exclude_matches_reference_algorithm() {
        // exclude_selftest :1154
        let mut includes1 = fill_lcg(0);
        let mut excludes = fill_lcg(1);
        let mut includes2 = includes1.clone();
        assert_eq!(includes1.as_slice(), includes2.as_slice());

        includes1.exclude(&mut excludes);
        exclude2(&mut includes2, &excludes);
        assert_eq!(includes1.as_slice(), includes2.as_slice());
    }

    #[test]
    fn removal_reference_selftest() {
        // ranges_selftest :1306-1360 (Test removal), числа захардкожены.
        let mut t = list(&[(0x0a00_0000, 0x0aff_ffff)]);
        t.sort_and_merge();
        remove_range(&mut t, 0x09ff_ffff, 0x09ff_ffff);
        remove_range(&mut t, 0x0b00_0000, 0x0b00_ffff);
        remove_range(&mut t, 0xc0a8_0000, 0xc0a8_ffff);
        t.sort_and_merge();
        assert_eq!(t.as_slice(), &[r(0x0a00_0000, 0x0aff_ffff)]);

        remove_range(&mut t, 0x0100_0000, 0x0a00_0000);
        remove_range(&mut t, 0x0aff_ffff, 0x0b00_0000);
        t.sort_and_merge();
        assert_eq!(t.as_slice(), &[r(0x0a00_0001, 0x0aff_fffe)]);

        remove_range(&mut t, 0x0a0a_0000, 0x0a0a_ffff);
        remove_range(&mut t, 0x0a14_0000, 0x0a14_ffff);
        t.sort_and_merge();
        assert_eq!(t.len(), 3);
        remove_range(&mut t, 0x0a0c_0000, 0x0a0c_ffff);
        t.sort_and_merge();
        assert_eq!(t.len(), 4);
        remove_range(&mut t, 0x0a0a_0a0a, 0x0a0c_0c0c);
        t.sort_and_merge();
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn ports_selftest() {
        // ranges_selftest :1363-1381 "80,1000-2000,1234,4444" (парсер — Задача 2).
        let mut t = list(&[(80, 80), (1000, 2000), (1234, 1234), (4444, 4444)]);
        t.sort_and_merge();
        assert_eq!(t.as_slice(), &[r(80, 80), r(1000, 2000), r(4444, 4444)]);
        assert!(t.is_contains(1500) && t.is_contains(80) && !t.is_contains(81));
    }

    #[test]
    fn exclude_starting_at_zero_or_one_applies_to_later_targets() {
        // Исправление бага B1 (C massip-rangesv4.c:766): исключение с begin 0 или 1,
        // целиком снимающее первую цель, обязано применяться и к последующим целям.
        let run = |inc: &[(u32, u32)], ex: (u32, u32)| {
            let mut t = list(inc);
            t.exclude(&mut list(&[ex]));
            t.as_slice().to_vec()
        };
        assert_eq!(run(&[(0, 10), (20, 30)], (0, 25)), [r(26, 30)]);
        assert_eq!(run(&[(1, 10), (20, 30)], (1, 25)), [r(26, 30)]);
        assert_eq!(run(&[(2, 10), (20, 30)], (2, 25)), [r(26, 30)]);
    }

    #[test]
    fn reversed_range_does_not_panic() {
        let mut t = list(&[(0x0a00_0005, 0x0a00_0003)]);
        assert_eq!(t.count(), 0xffff_ffff_ffff_ffff);
        t.optimize();
        let _ = t.pick(0);
    }

    #[test]
    fn full_space_counts_2_pow_32() {
        let mut t = list(&[(0, u32::MAX)]);
        assert_eq!(t.count(), 0x1_0000_0000);
        t.optimize();
        assert_eq!(t.pick(0), 0);
        assert_eq!(t.pick(0xffff_ffff), 0xffff_ffff);
    }

    #[test]
    fn merge_and_exclude_at_top_boundary() {
        // end+1 на 0xFFFFFFFF не должен переполняться.
        let mut t = list(&[(0xffff_fff0, u32::MAX), (0xffff_ff00, 0xffff_fff1)]);
        t.sort_and_merge();
        assert_eq!(t.as_slice(), &[r(0xffff_ff00, u32::MAX)]);

        let mut ex = list(&[(0xffff_fff0, u32::MAX)]);
        t.exclude(&mut ex);
        assert_eq!(t.as_slice(), &[r(0xffff_ff00, 0xffff_ffef)]);

        let mut all = list(&[(0, u32::MAX)]);
        let mut mid = list(&[(5, 5)]);
        all.exclude(&mut mid);
        assert_eq!(all.as_slice(), &[r(0, 4), r(6, u32::MAX)]);
        assert_eq!(all.count(), 0xffff_ffff);
    }

    /// Копия цикла `pick` из базы (двоичный поиск по префиксным суммам). `pick` сохраняет этот цикл, и копия, а не
    /// вызов, закрепляет его. Замена на `partition_point` отклонена: дифференциальный тест разошёлся с ней на списках с
    /// диапазоном `begin > end` (его размер оборачивается, и префиксные суммы немонотонны).
    /// `None` — цикл не завершается за 1000 шагов или выходит за список (на несортированных суммах).
    fn old_pick_mid(picker: &[u32], index: u64) -> Option<usize> {
        let maxmax = picker.len();
        let (mut min, mut max) = (0usize, maxmax);
        for _ in 0..1000 {
            let mid = min + (max - min) / 2;
            if mid >= maxmax {
                return None;
            }
            if index < u64::from(picker[mid]) {
                max = mid;
                continue;
            }
            if mid + 1 == maxmax || index < u64::from(picker[mid + 1]) {
                return Some(mid);
            }
            min = mid + 1;
        }
        None
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn rand_value(state: &mut u64) -> u32 {
        match splitmix(state) % 4 {
            0 => (splitmix(state) % 64) as u32,
            1 => (splitmix(state) % (1 << 16)) as u32,
            2 => [0, 1, 2, u32::MAX - 1, u32::MAX][(splitmix(state) % 5) as usize],
            _ => splitmix(state) as u32,
        }
    }

    #[test]
    fn pick_matches_the_kept_search() {
        // Случайные списки 1..64 диапазонов (в том числе `begin > end`, после `exclude` от 0.0.0.0, с оборачиванием
        // префиксных сумм): `pick` равен копии старого поиска на всех индексах меньше суммы и на трёх за концом.
        let mut state = 0x7069_636b_u64;
        let (mut compared, mut skipped, mut non_monotone) = (0u32, 0u32, 0u32);
        for case in 0..4000 {
            let mut l = RangeList::new();
            let reversed_heavy = case % 4 == 3;
            for _ in 0..1 + splitmix(&mut state) % 64 {
                let (b, e) = (rand_value(&mut state), rand_value(&mut state));
                if reversed_heavy {
                    l.add_range(b.max(e), b.min(e));
                    continue;
                }
                // половина диапазонов нормальные, остальные как попало (в том числе `begin > end`)
                match splitmix(&mut state) % 4 {
                    0 | 1 => l.add_range(b.min(e), b.max(e)),
                    2 => l.add_range(b, e),
                    // обратный диапазон (`begin > end`): его размер оборачивается и делает суммы немонотонными
                    _ => l.add_range(b.max(e), b.min(e)),
                }
            }
            if splitmix(&mut state).is_multiple_of(2) {
                l.sort_and_merge();
            }
            if splitmix(&mut state).is_multiple_of(3) {
                let mut x = RangeList::new();
                x.add_range(0, rand_value(&mut state));
                for _ in 0..splitmix(&mut state) % 5 {
                    let (b, e) = (rand_value(&mut state), rand_value(&mut state));
                    x.add_range(b.min(e), b.max(e));
                }
                l.exclude(&mut x);
            }
            l.optimize();
            let Some(picker) = l.picker.clone() else {
                continue;
            };
            if picker.windows(2).any(|w| w[0] > w[1]) {
                non_monotone += 1;
            }
            let count = l.count();
            let mut indices: Vec<u64> = if count <= 4096 {
                (0..count).collect()
            } else {
                let mut v: Vec<u64> = picker
                    .iter()
                    .flat_map(|&p| [u64::from(p), u64::from(p).wrapping_sub(1)])
                    .filter(|&i| i < count)
                    .collect();
                v.extend((0..64).map(|_| splitmix(&mut state) % count));
                v.extend([0, count - 1]);
                v
            };
            indices.extend([count, count + 1, count + 2]);
            for index in indices {
                let Some(mid) = old_pick_mid(&picker, index) else {
                    skipped += 1;
                    continue;
                };
                let want = std::panic::catch_unwind(|| {
                    l.list[mid]
                        .begin
                        .wrapping_add((index - u64::from(picker[mid])) as u32)
                });
                let got = std::panic::catch_unwind(|| l.pick(index));
                assert_eq!(got.ok(), want.ok(), "case {case} index {index}");
                compared += 1;
            }
        }
        assert!(compared > 50_000, "compared {compared}");
        eprintln!(
            "pick differential: compared {compared}, old search stuck {skipped}, non-monotone lists {non_monotone}"
        );
    }
}
