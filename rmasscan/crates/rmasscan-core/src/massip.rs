//! Объединённое пространство целей: IPv4-диапазоны × порты (AGPL-3.0).
//! Порт `src/massip.c` и `src/massip.h` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! IPv6 в v1 не поддерживается: его счётчик в C равен 0, поэтому индексы
//! и `range` не смещаются. Порты хранятся со смещениями протоколов
//! (`targets::TEMPL_*`, massip-port.h); для TCP смещение 0.

use crate::ranges::RangeList;

/// Диапазон индексов не помещается в 63 бита (main.c:1698-1704).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("target space too large: count_ipv4s * count_ports does not fit in 63 bits")]
pub struct RangeOverflow;

#[derive(Debug, Clone, Default)]
pub struct MassIp {
    ipv4: RangeList,
    ports: RangeList,
    /// `true` между `optimize` и следующим изменением списков; `pick` и
    /// `range` требуют `true`, иначе счётчики устарели.
    optimized: bool,
    count_ports: u64,
    count_ipv4s: u64,
    ipv4_index_threshold: u64,
}

impl MassIp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ipv4(&self) -> &RangeList {
        &self.ipv4
    }

    pub fn ports(&self) -> &RangeList {
        &self.ports
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
        self.ports.exclude(&mut exclude.ports);
    }

    /// massip.c:15 `massip_optimize`: сортировка/оптимизация списков и
    /// пересчёт счётчиков. Произведение считается с `wrapping_mul`, как
    /// `uint64_t` в C; переполнение ловит [`MassIp::try_range`].
    pub fn optimize(&mut self) {
        self.ipv4.optimize();
        self.ports.optimize();
        self.count_ports = self.ports.count();
        self.count_ipv4s = self.ipv4.count();
        self.ipv4_index_threshold = self.count_ipv4s.wrapping_mul(self.ports.count());
        self.optimized = true;
    }

    pub fn count_ports(&self) -> u64 {
        self.count_ports
    }

    pub fn count_ipv4s(&self) -> u64 {
        self.count_ipv4s
    }

    /// massip.h:36 `massip_range` без IPv6-слагаемого, с проверкой main.c:1698-1704:
    /// результат обязан помещаться в 63 бита, иначе `Err(RangeOverflow)`.
    pub fn try_range(&self) -> Result<u64, RangeOverflow> {
        // Из живых списков, как C `massip_range` (massip-rangesv6.c:170-180):
        // работает и до `optimize`.
        let total = u128::from(self.ipv4.count()) * u128::from(self.ports.count());
        if total >> 63 != 0 {
            return Err(RangeOverflow);
        }
        Ok(total as u64)
    }

    /// Число комбинаций IP/порт. Паникует при переполнении 63 бит: Task 10
    /// (валидация конфигурации) обязана сперва вызвать [`MassIp::try_range`].
    pub fn range(&self) -> u64 {
        assert!(self.optimized, "MassIp::range called before optimize");
        self.try_range()
            .expect("range overflow: validate with try_range first")
    }

    /// massip.c:27 `massip_pick` для IPv4. `index` должен быть < `range()`
    /// (в C иначе ветка IPv6 с делением на нулевой count_ipv6s); список
    /// должен быть оптимизирован и непуст.
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

    /// massip.c:45 `massip_has_ip` (IPv4).
    pub fn has_ip(&self, ip: u32) -> bool {
        self.ipv4.is_contains(ip)
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
        assert_eq!(space(0x7fff_ffff).try_range(), Err(RangeOverflow));
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
}
