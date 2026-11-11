//! Объединённое пространство целей: IPv4-диапазоны × порты (AGPL-3.0).
//! Порт `src/massip.c` и `src/massip.h` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! IPv6-список (`ipv6`) хранится, исключается и оптимизируется как в C
//! (massip.c:8-25) и входит в `range`/`try_range`. Нумерация индексов у C
//! двух видов, и они различаются:
//! - `-sL` (`massip_pick`, massip.c:27-43): IPv4 на `0..count_ipv4 * ports`,
//!   IPv6 выше; [`MassIp::pick_list`];
//! - transmit (main.c:336-373): IPv6 на `0..count_ipv6 * ports` (`range_ipv6`),
//!   IPv4 выше; [`MassIp::pick_transmit`].
//!
//! Без IPv6-целей оба порядка совпадают с прежним IPv4-порядком побайтно
//! ([`MassIp::pick`]). Порты хранятся со смещениями протоколов
//! (`targets::TEMPL_*`, massip-port.h); для TCP смещение 0.

use crate::ranges::RangeList;
use crate::ranges6::Range6List;
use crate::targets::{ParseError, add_target_string_v46};

/// Диапазон индексов не помещается в 63 бита (main.c:1698-1704).
///
/// `bits` это то, что C печатает как `requested is %u bits`: длина числа
/// `(count_ipv4 + count_ipv6) * count_ports` в битах (128 при переполнении
/// 128 бит и для `::/0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "scan range too large, max is 63-bits, requested is {bits} bits (scan range is the number of \
     IP addresses times the number of ports; an IPv6 subnet must be at least /66)"
)]
pub struct RangeOverflow {
    pub bits: u32,
}

/// Одна цель: адрес IPv4 или IPv6 (`ipaddress` C, массив `version`). Порт
/// передаётся рядом, а не внутри.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetIp {
    V4(u32),
    V6(u128),
}

impl Default for TargetIp {
    fn default() -> Self {
        TargetIp::V4(0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MassIp {
    ipv4: RangeList,
    ipv6: Range6List,
    ports: RangeList,
    /// `true` между `optimize` и следующим изменением списков; `pick` и
    /// `range` требуют `true`, иначе счётчики устарели.
    optimized: bool,
    count_ports: u64,
    count_ipv4s: u64,
    /// massip.c:21 `range6list_count(...).lo`: младшие 64 бита счёта.
    count_ipv6s: u64,
    ipv4_index_threshold: u64,
}

impl MassIp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ipv4(&self) -> &RangeList {
        &self.ipv4
    }

    pub fn ipv6(&self) -> &Range6List {
        &self.ipv6
    }

    pub fn ports(&self) -> &RangeList {
        &self.ports
    }

    /// Изменяемый доступ к IPv6-целям; сбрасывает признак `optimized`.
    pub fn ipv6_mut(&mut self) -> &mut Range6List {
        self.optimized = false;
        &mut self.ipv6
    }

    /// massip.c:72-100 `massip_add_target_string`: IPv4 и IPv6 через запятую
    /// или пробел. При ошибке списки не меняются.
    pub fn add_target_string(&mut self, s: &str) -> Result<(), ParseError> {
        self.optimized = false;
        add_target_string_v46(&mut self.ipv4, &mut self.ipv6, s)
    }

    /// Изменяемый доступ к целям; сбрасывает признак `optimized`.
    pub fn ipv4_mut(&mut self) -> &mut RangeList {
        self.optimized = false;
        &mut self.ipv4
    }

    /// Изменяемый доступ к портам; сбрасывает признак `optimized`. Порты
    /// можно добавлять между `apply_excludes` и `optimize` (main.c:1674-1675).
    pub fn ports_mut(&mut self) -> &mut RangeList {
        self.optimized = false;
        &mut self.ports
    }

    /// massip.c:8 `massip_apply_excludes`: исключения применяются к адресам
    /// и к портам. Вызывать до [`MassIp::optimize`] (main.c:1673 до :1684).
    pub fn apply_excludes(&mut self, exclude: &mut MassIp) {
        self.optimized = false;
        self.ipv4.exclude(&mut exclude.ipv4);
        self.ipv6.apply_excludes(&exclude.ipv6);
        self.ports.exclude(&mut exclude.ports);
    }

    /// massip.c:15 `massip_optimize`: сортировка/оптимизация списков и
    /// пересчёт счётчиков. Произведение считается с `wrapping_mul`, как
    /// `uint64_t` в C; переполнение ловит [`MassIp::try_range`].
    pub fn optimize(&mut self) {
        self.ipv4.optimize();
        self.ipv6.optimize();
        self.ports.optimize();
        self.count_ports = self.ports.count();
        self.count_ipv4s = self.ipv4.count();
        self.count_ipv6s = self.ipv6.count_u128() as u64;
        self.ipv4_index_threshold = self.count_ipv4s.wrapping_mul(self.ports.count());
        self.optimized = true;
    }

    pub fn count_ports(&self) -> u64 {
        self.count_ports
    }

    pub fn count_ipv4s(&self) -> u64 {
        self.count_ipv4s
    }

    /// massip.c:21: младшие 64 бита `range6list_count` (для `::/0` это
    /// `u64::MAX`; полное значение: `ipv6().count_u128()`).
    pub fn count_ipv6s(&self) -> u64 {
        self.count_ipv6s
    }

    /// massip.c:60-66 `massip_has_ipv6_targets`.
    pub fn has_ipv6_targets(&self) -> bool {
        !self.ipv6.is_empty()
    }

    /// massip-rangesv6.c:170-180 `massip_range` с проверкой main.c:1698-1704:
    /// `(count_ipv4 + count_ipv6) * count_ports` обязан помещаться в 63 бита,
    /// иначе `Err(RangeOverflow)`.
    ///
    /// Счёт идёт в `u128` без потерь: `count_u128() == u128::MAX` у `::/0` это
    /// маркер переполнения (massip-rangesv6.c:499-500), а не точное число, и
    /// даёт отказ. Исключение: ноль портов даёт ноль, как у C (0 в произведении),
    /// поэтому `--echo --range ::/0` без портов проходит проверку.
    ///
    /// Считает по живым спискам, как C, и работает до `optimize`. Но IPv6-список
    /// до `optimize` может хранить перекрытия и считаться дважды (как у C), так
    /// что вызывать после `optimize`/`apply_excludes`.
    pub fn try_range(&self) -> Result<u64, RangeOverflow> {
        let ports = u128::from(self.ports.count());
        if ports == 0 {
            return Ok(0);
        }
        let v6 = self.ipv6.count_u128();
        let total = if v6 == u128::MAX {
            None
        } else {
            u128::from(self.ipv4.count())
                .checked_add(v6)
                .and_then(|ips| ips.checked_mul(ports))
        };
        match total {
            Some(t) if t >> 63 == 0 => Ok(t as u64),
            Some(t) => Err(RangeOverflow {
                bits: 128 - t.leading_zeros(),
            }),
            None => Err(RangeOverflow { bits: 128 }),
        }
    }

    /// main.c:258-260 `range_ipv6 = count_ipv6 * rangelist_count(ports)`:
    /// число индексов transmit, отданных IPv6 (низ диапазона). `count_ipv6` это
    /// младшие 64 бита (main.c:218); после [`MassIp::try_range`] они точны.
    pub fn range_ipv6(&self) -> u64 {
        assert!(self.optimized, "MassIp::range_ipv6 called before optimize");
        self.count_ipv6s.wrapping_mul(self.count_ports)
    }

    /// Число комбинаций IP/порт. Паникует при переполнении 63 бит: Task 10
    /// (валидация конфигурации) обязана сперва вызвать [`MassIp::try_range`].
    pub fn range(&self) -> u64 {
        assert!(self.optimized, "MassIp::range called before optimize");
        self.try_range()
            .expect("range overflow: validate with try_range first")
    }

    /// IPv4-нумерация `massip_pick` (massip.c:30-34, ветка `index <
    /// ipv4_index_threshold`): единственная нумерация без IPv6-целей, там она
    /// совпадает и с `-sL`, и с transmit. При IPv6-целях пользуйтесь
    /// [`MassIp::pick_list`] (`-sL`) или [`MassIp::pick_transmit`] (transmit):
    /// у них разный порядок. `index` должен быть меньше
    /// `count_ipv4s * count_ports`; список должен быть оптимизирован и непуст.
    ///
    /// Порт возвращается в пространстве Templ (massip-port.h): для UDP это
    /// `TEMPL_UDP + порт` и т. д.; для TCP значение равно номеру порта.
    pub fn pick(&self, index: u64) -> (u32, u32) {
        assert!(
            self.optimized,
            "MassIp::pick called before optimize (or lists changed since)"
        );
        assert!(
            index < self.ipv4_index_threshold,
            "massip pick: index out of range"
        );
        let ip = self.ipv4.pick(index % self.count_ipv4s);
        let port = self.ports.pick(index / self.count_ipv4s);
        (ip, port)
    }

    /// massip.c:27-43 `massip_pick`, порядок `-sL` (main-listscan.c:44): IPv4 на
    /// `0..count_ipv4 * ports`, IPv6 выше (`index - ipv4_index_threshold`).
    /// `index` должен быть меньше `range()` (в C иначе деление на нулевой
    /// `count_ipv6s`); список оптимизирован.
    pub fn pick_list(&self, index: u64) -> (TargetIp, u32) {
        assert!(
            self.optimized,
            "MassIp::pick_list called before optimize (or lists changed since)"
        );
        if index < self.ipv4_index_threshold {
            let (ip, port) = self.pick(index);
            return (TargetIp::V4(ip), port);
        }
        // massip.c:38-41
        let index = index - self.ipv4_index_threshold;
        assert!(index < self.range_ipv6(), "massip pick: index out of range");
        let ip = self.ipv6.pick(index % self.count_ipv6s);
        let port = self.ports.pick(index / self.count_ipv6s);
        (TargetIp::V6(ip), port)
    }

    /// Порядок transmit (main.c:336-373): `xxx < range_ipv6` это IPv6
    /// (`range6list_pick(xxx % count_ipv6)`, порт `xxx / count_ipv6`), иначе
    /// IPv4 с индексом `xxx - range_ipv6`. Третье значение это `xXx` на момент
    /// SYN-cookie: после вычитания `range_ipv6` у IPv4 (main.c:369 до :381
    /// `(unsigned)xXx`), без вычитания у IPv6. Без IPv6-целей `range_ipv6 == 0`
    /// и всё тождественно [`MassIp::pick`].
    pub fn pick_transmit(&self, xxx: u64) -> (TargetIp, u32, u64) {
        let range_ipv6 = self.range_ipv6();
        if xxx < range_ipv6 {
            let ip = self.ipv6.pick(xxx % self.count_ipv6s);
            let port = self.ports.pick(xxx / self.count_ipv6s);
            (TargetIp::V6(ip), port, xxx)
        } else {
            let x = xxx - range_ipv6;
            let (ip, port) = self.pick(x);
            (TargetIp::V4(ip), port, x)
        }
    }

    /// massip.c:45 `massip_has_ip` (IPv4).
    pub fn has_ip(&self, ip: u32) -> bool {
        self.ipv4.is_contains(ip)
    }

    /// massip.c:45 `massip_has_ip` (IPv6).
    pub fn has_ip6(&self, ip: u128) -> bool {
        self.ipv6.is_contains(ip)
    }

    /// massip.c:53 `massip_has_port`.
    pub fn has_port(&self, port: u32) -> bool {
        self.ports.is_contains(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets;

    #[test]
    fn excludes_then_optimize_change_counts_and_pick() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.0/30").unwrap();
        targets::parse_ports(t.ports_mut(), "80,443").unwrap();
        let mut ex = MassIp::new();
        targets::add_target_string(ex.ipv4_mut(), "10.0.0.1-10.0.0.2").unwrap();
        t.apply_excludes(&mut ex);
        t.optimize();
        assert_eq!(t.range(), 2 * 2);
        assert_eq!(t.pick(0), (0x0a00_0000, 80));
        assert_eq!(t.pick(1), (0x0a00_0003, 80));
        assert_eq!(t.pick(2), (0x0a00_0000, 443));
        assert_eq!(t.pick(3), (0x0a00_0003, 443));
    }

    #[test]
    fn excluded_port_shrinks_port_space() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.1").unwrap();
        targets::parse_ports(t.ports_mut(), "80-82").unwrap();
        let mut ex = MassIp::new();
        targets::parse_ports(ex.ports_mut(), "81").unwrap();
        t.apply_excludes(&mut ex);
        t.optimize();
        assert_eq!(t.range(), 2);
        assert_eq!(t.pick(1).1, 82);
    }

    fn space(ports_end: u32) -> MassIp {
        let mut t = MassIp::new();
        t.ipv4_mut().add_range(0, u32::MAX); // 2^32
        t.ports_mut().add_range(0, ports_end);
        t
    }

    #[test]
    fn range_overflow_boundary() {
        // 2^32 * 2^31 = 2^63: отклоняется (main.c:1698-1704).
        assert_eq!(
            space(0x7fff_ffff).try_range(),
            Err(RangeOverflow { bits: 64 })
        );
        // 2^32 * (2^31 - 1) < 2^63: принимается.
        assert_eq!(
            space(0x7fff_fffe).try_range(),
            Ok((1u64 << 32) * ((1u64 << 31) - 1))
        );
    }

    #[test]
    fn try_range_same_before_and_after_optimize() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.0/30").unwrap();
        targets::parse_ports(t.ports_mut(), "80,443").unwrap();
        let before = t.try_range();
        t.optimize();
        assert_eq!(before, Ok(8));
        assert_eq!(t.try_range(), before);
    }

    #[test]
    fn ports_may_be_added_between_excludes_and_optimize() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.1").unwrap();
        t.apply_excludes(&mut MassIp::new());
        t.ports_mut().add_range(80, 80); // main.c:1674-1675
        t.optimize();
        assert_eq!(t.pick(0), (0x0a00_0001, 80));
    }

    #[test]
    #[should_panic(expected = "before optimize")]
    fn pick_before_optimize_panics() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.1").unwrap();
        targets::parse_ports(t.ports_mut(), "80").unwrap();
        t.pick(0);
    }

    #[test]
    #[should_panic(expected = "before optimize")]
    fn pick_after_add_following_optimize_panics() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.1").unwrap();
        targets::parse_ports(t.ports_mut(), "80").unwrap();
        t.optimize();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.2").unwrap();
        t.pick(0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn pick_out_of_range_panics() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.1").unwrap();
        targets::parse_ports(t.ports_mut(), "80").unwrap();
        t.optimize();
        t.pick(1);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn pick_on_empty_list_panics() {
        let mut t = MassIp::new();
        t.optimize();
        t.pick(0);
    }

    #[test]
    fn udp_port_is_returned_in_templ_space() {
        let mut t = MassIp::new();
        targets::add_target_string(t.ipv4_mut(), "10.0.0.1").unwrap();
        t.ports_mut()
            .add_range(targets::TEMPL_UDP + 53, targets::TEMPL_UDP + 53);
        t.optimize();
        assert_eq!(t.pick(0).1, 65589);
    }

    #[test]
    fn empty_range_is_zero() {
        let mut t = MassIp::new();
        t.optimize();
        assert_eq!(t.range(), 0);
    }
    #[test]
    fn ipv6_targets_excludes_and_counts_follow_c() {
        // massip.c:112-145 massip_selftest, plus massip_apply_excludes (:8-13)
        // and massip_optimize (:15-25) for the IPv6 list.
        let mut t = MassIp::new();
        t.add_target_string("2607:f8b0:4002:801::2004/124,1111::1")
            .unwrap();
        t.ports_mut().add_range(80, 80);
        let mut ex = MassIp::new();
        ex.add_target_string("2607:f8b0:4002:801::2004/126,1111::/16")
            .unwrap();
        t.apply_excludes(&mut ex);
        t.optimize();
        assert_eq!(t.count_ipv6s(), 12);
        assert!(t.has_ipv6_targets());
        assert!(t.has_ip6(0x2607_f8b0_4002_0801_0000_0000_0000_2004 + 4));
        assert!(!t.has_ip6(0x2607_f8b0_4002_0801_0000_0000_0000_2004));
        // massip.c:60-66 `massip_has_ipv6_targets`
        assert!(!MassIp::new().has_ipv6_targets());
    }

    /// Invariant: with no IPv6 target the IPv4 side is exactly as before the
    /// IPv6 list existed (range, pick, counts).
    #[test]
    fn ipv6_list_does_not_change_pure_ipv4_numbers() {
        let mut t = MassIp::new();
        t.add_target_string("10.0.0.0/30").unwrap();
        t.ports_mut().add_range(80, 81);
        t.optimize();
        assert_eq!(t.count_ipv6s(), 0);
        assert_eq!(t.range(), 8);
        assert_eq!(t.pick(0), (0x0a00_0000, 80));
        assert_eq!(t.pick(5), (0x0a00_0001, 81));
    }

    #[test]
    fn massip_add_target_string_reports_errors_atomically() {
        let mut t = MassIp::new();
        assert!(t.add_target_string("10.0.0.1,::1,nope").is_err());
        assert!(t.ipv4().is_empty() && t.ipv6().is_empty());
    }

    fn mixed(v6: &str, v4: &str, ports: &str) -> MassIp {
        let mut t = MassIp::new();
        t.add_target_string(&format!("{v6},{v4}")).unwrap();
        targets::parse_ports(t.ports_mut(), ports).unwrap();
        t.optimize();
        t
    }

    const V6_10: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0010;

    /// main.c:1698-1704 `massip_range` is `(count_ipv4 + count_ipv6) * ports`.
    #[test]
    fn try_range_adds_ipv6_to_ipv4_before_multiplying_by_ports() {
        let t = mixed("2001:db8::10-2001:db8::11", "192.0.2.1-192.0.2.3", "80,443");
        assert_eq!(t.try_range(), Ok((3 + 2) * 2));
        assert_eq!(t.range(), 10);
        assert_eq!(t.range_ipv6(), 4);
    }

    /// Review Focus 1 (`ipv6_full_space_and_63bit_limit`, half 2) against the C
    /// binary: `-sL --seed 42 2001:db8::/N -p80` prints "requested is 65 bits"
    /// for /64, 64 for /65 and 128 for `::/0`; /66 passes.
    #[test]
    fn ipv6_full_space_and_63bit_limit() {
        let one = |v6: &str, ports: &str| {
            let mut t = MassIp::new();
            t.add_target_string(v6).unwrap();
            targets::parse_ports(t.ports_mut(), ports).unwrap();
            t.optimize();
            t.try_range()
        };
        assert_eq!(one("2001:db8::/64", "80"), Err(RangeOverflow { bits: 65 }));
        assert_eq!(one("2001:db8::/65", "80"), Err(RangeOverflow { bits: 64 }));
        assert_eq!(one("2001:db8::/66", "80"), Ok(1u64 << 62));
        // main.c:1698: /66 with two ports is 2^63, 64 bits
        assert_eq!(
            one("2001:db8::/66", "80,81"),
            Err(RangeOverflow { bits: 64 })
        );
        // `::/0` is the overflow marker u128::MAX (massip-rangesv6.c:499-500): 128 bits
        assert_eq!(one("::/0", "80"), Err(RangeOverflow { bits: 128 }));
        // the marker times zero ports is zero in C too, so `--echo --range ::/0` passes
        assert_eq!(one("::/0", ""), Ok(0));
        // IPv4 added before the multiplication: 2^62 + 2^32 addresses * 65536 ports
        let mut t = MassIp::new();
        t.add_target_string("2001:db8::/66,0.0.0.0/0").unwrap();
        targets::parse_ports(t.ports_mut(), "0-65535").unwrap();
        t.optimize();
        assert_eq!(t.try_range(), Err(RangeOverflow { bits: 79 }));
    }

    /// massip.c:30-43 (`-sL`): IPv4 first on `0..count_ipv4*ports`, then IPv6;
    /// the port divides by the count of the family being picked.
    #[test]
    fn pick_list_puts_ipv4_low_and_ipv6_high() {
        let t = mixed("2001:db8::10-2001:db8::11", "192.0.2.1-192.0.2.3", "80,443");
        let v4 = |n: u32| 0xc000_0200 + n;
        let mut got = Vec::new();
        for x in 0..10 {
            got.push(t.pick_list(x));
        }
        let want = [
            (TargetIp::V4(v4(1)), 80),
            (TargetIp::V4(v4(2)), 80),
            (TargetIp::V4(v4(3)), 80),
            (TargetIp::V4(v4(1)), 443),
            (TargetIp::V4(v4(2)), 443),
            (TargetIp::V4(v4(3)), 443),
            (TargetIp::V6(V6_10), 80),
            (TargetIp::V6(V6_10 + 1), 80),
            (TargetIp::V6(V6_10), 443),
            (TargetIp::V6(V6_10 + 1), 443),
        ];
        assert_eq!(got, want);
    }

    /// main.c:336-373 (transmit): IPv6 first on `0..range_ipv6`, IPv4 after with
    /// `range_ipv6` subtracted; the third value is `xXx` after that subtraction
    /// (main.c:369 precedes the cookie at :381).
    #[test]
    fn pick_transmit_puts_ipv6_low_and_ipv4_high() {
        let t = mixed("2001:db8::10-2001:db8::11", "192.0.2.1-192.0.2.3", "80,443");
        let v4 = |n: u32| 0xc000_0200 + n;
        let want = [
            (TargetIp::V6(V6_10), 80, 0),
            (TargetIp::V6(V6_10 + 1), 80, 1),
            (TargetIp::V6(V6_10), 443, 2),
            (TargetIp::V6(V6_10 + 1), 443, 3),
            (TargetIp::V4(v4(1)), 80, 0),
            (TargetIp::V4(v4(2)), 80, 1),
            (TargetIp::V4(v4(3)), 80, 2),
            (TargetIp::V4(v4(1)), 443, 3),
            (TargetIp::V4(v4(2)), 443, 4),
            (TargetIp::V4(v4(3)), 443, 5),
        ];
        for (x, w) in want.iter().enumerate() {
            assert_eq!(t.pick_transmit(x as u64), *w, "index {x}");
        }
    }

    /// Invariant: with no IPv6 target all three pickers agree.
    #[test]
    fn pure_ipv4_pickers_agree() {
        let mut t = MassIp::new();
        t.add_target_string("198.18.0.0/28").unwrap();
        targets::parse_ports(t.ports_mut(), "80,443").unwrap();
        t.optimize();
        assert_eq!(t.range_ipv6(), 0);
        for x in 0..t.range() {
            let (ip, port) = t.pick(x);
            assert_eq!(t.pick_list(x), (TargetIp::V4(ip), port));
            assert_eq!(t.pick_transmit(x), (TargetIp::V4(ip), port, x));
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn pick_list_past_the_end_panics() {
        mixed("2001:db8::10", "192.0.2.1", "80").pick_list(2);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn pick_transmit_past_the_end_panics() {
        mixed("2001:db8::10", "192.0.2.1", "80").pick_transmit(2);
    }
}
