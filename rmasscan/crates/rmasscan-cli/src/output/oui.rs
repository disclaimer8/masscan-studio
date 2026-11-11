//! Строка производителя по OUI (AGPL-3.0). Порт `oui_from_mac` (`output.c:687–739`) masscan © Robert David Graham:
//! это собственная таблица masscan внутри `output.c`, не сторонний список. Порядок и значения как в C (46 записей).

/// `oui_from_mac`: первые три байта как число; неизвестный OUI даёт пустую строку (`output.c:737`).
pub fn oui_from_mac(mac: &[u8; 6]) -> &'static str {
    let oui = u32::from(mac[0]) << 16 | u32::from(mac[1]) << 8 | u32::from(mac[2]);
    match oui {
        0x0001c0 => "Compulab",
        0x000732 => "Aaeon",
        0x00089b => "ICPelec",
        0x000c29 => "VMware",
        0x001075 => "Seagate",
        0x001132 => "Synology",
        0x022618 => "Asus",
        0x0022b0 => "D-Link",
        0x00236c => "Apple",
        0x0016cb => "Apple",
        0x001e06 => "Odroid",
        0x001ff3 => "Apple",
        0x002590 => "Supermicro",
        0x04421a => "Asus",
        0x08cc68 => "Cisco",
        0x0c9d92 => "Asus",
        0x244bfe => "Asus",
        0x244ce3 => "Amazon",
        0x28cdc1 => "RPi 22-02",
        0x2c27d7 => "HP",
        0x3497f6 => "Asus",
        0x38f73d => "Amazon",
        0x3a3541 => "RPi 19-12",
        0x3c22fb => "Apple",
        0x404a03 => "Zyxel",
        0x4c9eff => "Zyxel",
        0x5855ca => "Apple",
        0x60a44c => "Asus",
        0x640bd7 => "Apple",
        0x6c72e7 => "Apple",
        0x8c3bad => "Netgear",
        0x9003b7 => "Parrot",
        0x9009d0 => "Synology",
        0x94a408 => "Trolink",
        0x94dbc9 => "Azurewave",
        0xa0cec8 => "CeLink",
        0xacbc32 => "Apple",
        0xb827eb => "RPi 12-03",
        0xc05627 => "Belkin",
        0xc0c1c0 => "Cisco-Linksys",
        0xd83add => "RPi 22-11",
        0xdca4ca => "Apple",
        0xdca632 => "RPi 19-03",
        0xe45f01 => "RPi 20-07",
        0xe4956e => "[random]",
        0xfcecda => "Ubiquiti",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::oui_from_mac;

    #[test]
    fn known_and_unknown_ouis_follow_c() {
        assert_eq!(oui_from_mac(&[0xb8, 0x27, 0xeb, 1, 2, 3]), "RPi 12-03");
        assert_eq!(oui_from_mac(&[0x00, 0x0c, 0x29, 0, 0, 1]), "VMware");
        assert_eq!(oui_from_mac(&[0xE4, 0x95, 0x6E, 0, 0, 1]), "[random]");
        assert_eq!(oui_from_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), "");
        assert_eq!(oui_from_mac(&[0x02, 0x00, 0x00, 0, 0, 1]), "");
    }
}
