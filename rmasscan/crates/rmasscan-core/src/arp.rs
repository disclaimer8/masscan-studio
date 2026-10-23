//! Кодек ARP для Ethernet/IPv4 (AGPL-3.0). Порт запроса и разбора ответа из
//! `src/stack-arpv4.c` (`stack_arp_resolve` :103, `proto_arp_parse` :43) и
//! `proto-preprocess.c:parse_arp`, masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Отличия от C, намеренные: C пропускает hw type 6 и проверяет длины через
//! `&&` (`protocol_length != 4 && hardware_length != 6`, то есть пропускает
//! кадр с одной неверной длиной); здесь допустимо только 1/0x0800/6/4. VLAN
//! возвращает [`ArpError::Vlan`]. Источник Ethernet должен совпадать с
//! sender MAC в ARP.

/// Длина кадра запроса: ARP 42 байта, дополнение до минимума Ethernet 60.
pub const ARP_FRAME_LEN: usize = 60;
const ETH_LEN: usize = 14;
const ARP_LEN: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArpError {
    #[error("truncated ARP frame ({0} bytes)")]
    Truncated(usize),
    #[error("VLAN-tagged frames are not supported")]
    Vlan,
    #[error("not an ARP frame (ethertype 0x{0:04x})")]
    NotArp(u16),
    #[error("unsupported hardware type {0}")]
    BadHardwareType(u16),
    #[error("unsupported protocol type 0x{0:04x}")]
    BadProtocolType(u16),
    #[error("bad address lengths hw={hw} proto={proto}")]
    BadLengths { hw: u8, proto: u8 },
    #[error("unsupported ARP opcode {0}")]
    BadOpcode(u16),
}

/// Разобранный ARP-пакет.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub eth_src: [u8; 6],
    pub op: ArpOp,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

fn mac_at(b: &[u8], i: usize) -> Option<[u8; 6]> {
    b.get(i..i + 6)?.try_into().ok()
}

fn ip_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// Запрос "кто имеет `target_ip`", stack-arpv4.c:121-160 (без VLAN).
pub fn encode_request(my_mac: [u8; 6], my_ip: u32, target_ip: u32) -> [u8; ARP_FRAME_LEN] {
    let mut f = [0u8; ARP_FRAME_LEN];
    f[0..6].fill(0xff);
    f[6..12].copy_from_slice(&my_mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
    f[22..28].copy_from_slice(&my_mac);
    f[28..32].copy_from_slice(&my_ip.to_be_bytes());
    // f[32..38] target MAC = 0.
    f[38..42].copy_from_slice(&target_ip.to_be_bytes());
    f
}

/// Кадр ответа, нужен тестам и отладке (в C ответы шлёт `stack_arp_incoming_request`).
pub fn encode_reply(
    sender_mac: [u8; 6],
    sender_ip: u32,
    target_mac: [u8; 6],
    target_ip: u32,
) -> [u8; ARP_FRAME_LEN] {
    let mut f = [0u8; ARP_FRAME_LEN];
    f[0..6].copy_from_slice(&target_mac);
    f[6..12].copy_from_slice(&sender_mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    f[22..28].copy_from_slice(&sender_mac);
    f[28..32].copy_from_slice(&sender_ip.to_be_bytes());
    f[32..38].copy_from_slice(&target_mac);
    f[38..42].copy_from_slice(&target_ip.to_be_bytes());
    f
}

/// Разбирает Ethernet-кадр с ARP. Границы проверяются до чтения.
pub fn decode(frame: &[u8]) -> Result<ArpPacket, ArpError> {
    if frame.len() < ETH_LEN + ARP_LEN {
        // Тип можно прочитать, если он есть, чтобы VLAN назвать честно.
        if let Some(t) = frame.get(12..14)
            && matches!(u16::from_be_bytes([t[0], t[1]]), 0x8100 | 0x88a8 | 0x9100)
        {
            return Err(ArpError::Vlan);
        }
        return Err(ArpError::Truncated(frame.len()));
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0806 => {}
        0x8100 | 0x88a8 | 0x9100 => return Err(ArpError::Vlan),
        other => return Err(ArpError::NotArp(other)),
    }
    let a = &frame[ETH_LEN..];
    let hw = u16::from_be_bytes([a[0], a[1]]);
    let proto = u16::from_be_bytes([a[2], a[3]]);
    if hw != 1 {
        return Err(ArpError::BadHardwareType(hw));
    }
    if proto != 0x0800 {
        return Err(ArpError::BadProtocolType(proto));
    }
    if a[4] != 6 || a[5] != 4 {
        return Err(ArpError::BadLengths {
            hw: a[4],
            proto: a[5],
        });
    }
    let op = match u16::from_be_bytes([a[6], a[7]]) {
        1 => ArpOp::Request,
        2 => ArpOp::Reply,
        other => return Err(ArpError::BadOpcode(other)),
    };
    let bad = ArpError::Truncated(frame.len());
    Ok(ArpPacket {
        eth_src: mac_at(frame, 6).ok_or(bad.clone())?,
        op,
        sender_mac: mac_at(a, 8).ok_or(bad.clone())?,
        sender_ip: ip_at(a, 14).ok_or(bad.clone())?,
        target_mac: mac_at(a, 18).ok_or(bad.clone())?,
        target_ip: ip_at(a, 24).ok_or(bad)?,
    })
}

/// Ожидающее разрешение адреса (`stack_arp_resolve`). Принимает только ответ,
/// подходящий под запрос; чужой ответ состояние не меняет.
#[derive(Clone, Debug)]
pub struct PendingResolve {
    my_mac: [u8; 6],
    my_ip: u32,
    target_ip: u32,
    resolved: Option<[u8; 6]>,
}

impl PendingResolve {
    pub fn new(my_mac: [u8; 6], my_ip: u32, target_ip: u32) -> Self {
        Self {
            my_mac,
            my_ip,
            target_ip,
            resolved: None,
        }
    }

    pub fn request_frame(&self) -> [u8; ARP_FRAME_LEN] {
        encode_request(self.my_mac, self.my_ip, self.target_ip)
    }

    pub fn resolved(&self) -> Option<[u8; 6]> {
        self.resolved
    }

    /// Предлагает кадр. `Some(mac)` только когда это ответ (opcode 2) нам
    /// (`ip_dst == my_ip`, `mac_dst == my_mac`) от нужного хоста
    /// (`ip_src == target_ip`) с пригодным sender MAC (не нулевой, не
    /// групповой, равен Ethernet-источнику). Первый подходящий ответ
    /// фиксируется, последующие его не меняют.
    pub fn offer(&mut self, frame: &[u8]) -> Option<[u8; 6]> {
        if self.resolved.is_some() {
            return self.resolved;
        }
        let p = decode(frame).ok()?;
        let suitable = p.op == ArpOp::Reply
            && p.target_ip == self.my_ip
            && p.target_mac == self.my_mac
            && p.sender_ip == self.target_ip
            && p.sender_mac == p.eth_src
            && p.sender_mac != [0u8; 6]
            && p.sender_mac[0] & 1 == 0;
        if suitable {
            self.resolved = Some(p.sender_mac);
        }
        self.resolved
    }
}
