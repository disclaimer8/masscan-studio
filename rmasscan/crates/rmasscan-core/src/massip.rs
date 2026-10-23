//! Объединённое пространство целей: IPv4-диапазоны × порты (AGPL-3.0).
//! Порт `src/massip.c` и `src/massip.h` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! IPv6 в v1 не поддерживается: его счётчик в C равен 0, поэтому индексы
//! и `range` не смещаются. Порты хранятся со смещениями протоколов
//! (`targets::TEMPL_*`, massip-port.h); для TCP смещение 0.

use crate::ranges::RangeList;

/// Диапазон индексов не помещается в 63 бита (main.c:1683-1689).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("target space too large: count_ipv4s * count_ports does not fit in 63 bits")]
pub struct RangeOverflow;

#[derive(Debug, Clone, Default)]
pub struct MassIp {
    pub ipv4: RangeList,
    pub ports: RangeList,
    count_ports: u64,
    count_ipv4s: u64,
    ipv4_index_threshold: u64,
}

impl MassIp {
    pub fn new() -> Self {
        Self::default()
    }

    /// massip.c:8 `massip_apply_excludes`: исключения применяются к адресам
    /// и к портам. Вызывать до [`MassIp::optimize`] (main.c:1655 до :1670).
    pub fn apply_excludes(&mut self, exclude: &mut MassIp) {
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
    }

    pub fn count_ports(&self) -> u64 {
        self.count_ports
    }

    pub fn count_ipv4s(&self) -> u64 {
        self.count_ipv4s
    }

    /// massip.h:36 `massip_range` без IPv6-слагаемого, с проверкой main.c:1683:
    /// результат обязан помещаться в 63 бита, иначе `Err(RangeOverflow)`.
    pub fn try_range(&self) -> Result<u64, RangeOverflow> {
        let total = u128::from(self.count_ipv4s) * u128::from(self.count_ports);
        if total >> 63 != 0 {
            return Err(RangeOverflow);
        }
        Ok(total as u64)
    }

    /// Число комбинаций IP/порт. Паникует при переполнении 63 бит: Task 10
    /// (валидация конфигурации) обязана сперва вызвать [`MassIp::try_range`].
    pub fn range(&self) -> u64 {
        self.try_range()
            .expect("range overflow: validate with try_range first")
    }

    /// massip.c:27 `massip_pick` для IPv4. `index` должен быть < `range()`
    /// (в C иначе ветка IPv6 с делением на нулевой count_ipv6s); список
    /// должен быть оптимизирован и непуст.
    pub fn pick(&self, index: u64) -> (u32, u32) {
        assert!(
            index < self.ipv4_index_threshold,
            "massip pick: index out of range"
        );
        let ip = self.ipv4.pick(index % self.count_ipv4s);
        let port = self.ports.pick(index / self.count_ipv4s);
        (ip, port)
    }

    /// massip.c:52 `massip_has_ip` (IPv4).
    pub fn has_ip(&self, ip: u32) -> bool {
        self.ipv4.is_contains(ip)
    }

    /// massip.c:60 `massip_has_port`.
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
        targets::add_target_string(&mut t.ipv4, "10.0.0.0/30").unwrap();
        targets::parse_ports(&mut t.ports, "80,443").unwrap();
        let mut ex = MassIp::new();
        targets::add_target_string(&mut ex.ipv4, "10.0.0.1-10.0.0.2").unwrap();
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
        targets::add_target_string(&mut t.ipv4, "10.0.0.1").unwrap();
        targets::parse_ports(&mut t.ports, "80-82").unwrap();
        let mut ex = MassIp::new();
        targets::parse_ports(&mut ex.ports, "81").unwrap();
        t.apply_excludes(&mut ex);
        t.optimize();
        assert_eq!(t.range(), 2);
        assert_eq!(t.pick(1).1, 82);
    }

    #[test]
    fn range_overflow_is_rejected() {
        let mut t = MassIp::new();
        targets::add_target_string(&mut t.ipv4, "0.0.0.0/0").unwrap();
        targets::parse_ports(&mut t.ports, "0-65535").unwrap();
        t.optimize();
        assert_eq!(t.try_range(), Ok(1u64 << 48));
        t.ports.add_range(0, 0x9000_0000);
        t.optimize();
        assert_eq!(t.try_range(), Err(RangeOverflow));
    }

    #[test]
    fn empty_range_is_zero() {
        let mut t = MassIp::new();
        t.optimize();
        assert_eq!(t.range(), 0);
    }
}
