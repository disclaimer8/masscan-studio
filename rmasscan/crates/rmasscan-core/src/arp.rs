//! Кодек ARP для Ethernet/IPv4 (AGPL-3.0). Порт запроса и разбора ответа из
//! `src/stack-arpv4.c` (`stack_arp_resolve` :103, `proto_arp_parse` :52) и
//! `proto-preprocess.c:parse_arp`, masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), и ответчика на запросы
//! к нашим адресам (`stack_arp_incoming_request`, `src/stack-arpv4.c:282-363`).
//!
//! Отличия [`decode`] (резолвер и ответы ARP-скана) от C, намеренные: C пропускает hw type 6 и проверяет длины через
//! `&&` (`protocol_length != 4 && hardware_length != 6`, то есть пропускает
//! кадр с одной неверной длиной); здесь допустимо только 1/0x0800/6/4. VLAN
//! возвращает [`ArpError::Vlan`]. Источник Ethernet должен совпадать с
//! sender MAC в ARP. Ответчик ([`incoming_request`], [`answer_request`]) принимает запрос ровно как C, со всеми этими
//! странностями: его ответ уходит на провод и обязан совпасть с ответом C.

use crate::bytes::{array_at, be32_at};

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

/// Кадр ответа ARP (60 байт, дополнение нулями): Ethernet от `sender_mac` к `target_mac`, opcode 2, отправитель
/// `sender_mac`/`sender_ip`, получатель `target_mac`/`target_ip`. Раскладка `stack_arp_incoming_request`
/// (`src/stack-arpv4.c:301-356`); им строит ответ [`answer_request`].
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
    // Кадр не короче 42 байт (проверено выше): чтения ниже не отказывают, `Truncated` остаётся прежней защитой.
    let bad = || ArpError::Truncated(frame.len());
    Ok(ArpPacket {
        eth_src: array_at::<6>(frame, 6).ok_or_else(bad)?,
        op,
        sender_mac: array_at::<6>(a, 8).ok_or_else(bad)?,
        sender_ip: be32_at(a, 14).ok_or_else(bad)?,
        target_mac: array_at::<6>(a, 18).ok_or_else(bad)?,
        target_ip: be32_at(a, 24).ok_or_else(bad)?,
    })
}

/// Запрос ARP, на который отвечает C, в полях, которые C из него берёт.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncomingRequest {
    /// `request.mac_src`: 6 байт с `px + 22`, какой бы ни была длина адреса оборудования в заголовке
    /// (`src/stack-arpv4.c:81`, копия `:338`, `:350`).
    pub sender_mac: [u8; 6],
    /// `ip_src`: 4 байта сразу за адресом оборудования отправителя (`:84`).
    pub sender_ip: u32,
    /// `ip_dst`: 4 байта за адресом оборудования получателя (`:89`); C сравнивает его с нашим адресом.
    pub target_ip: u32,
}

/// Кадр Ethernet, на который C зовёт `stack_arp_incoming_request` и тот принимает его как запрос
/// (`src/main.c:799-887`, `src/stack-arpv4.c:52-94`, `:309-327`), без проверки адреса назначения: `None`, если C
/// не ответил бы ни на какой наш адрес. Проверки, как у C:
/// - кадр не длиннее 1514 байт (`src/main.c:799`);
/// - EtherType 0x0806 в байтах 12..14: C разбирает запрос с фиксированного смещения 14 (`proto_arp_parse(&request,
///   px, 14, length)`, `src/stack-arpv4.c:309`), а у кадра с тегом 802.1Q или 802.1ad и у LLC/SNAP, где
///   `preprocess_frame` находит ARP дальше (`src/proto-preprocess.c:334-338`, `:473-497`), байты 16..18 это
///   EtherType тега (0x0806, 0x8100) или байты LLC (0x0300, 0xaaaa), а не 0x0800, так что запрос с тегом у C ответа
///   не получает никогда;
/// - заголовок ARP и `2 × hl + 2 × pl` байт адресов в кадре (`VERIFY_REMAINING`, `src/proto-preprocess.c:599`, `:609`,
///   `src/stack-arpv4.c:59`, `:79`);
/// - opcode 1 (`src/main.c:879-880`), тип протокола 0x0800, тип оборудования 1 или 6 и отказ, только если неверны
///   обе длины (`protocol_length != 4 && hardware_length != 6`, `src/stack-arpv4.c:70-75`).
///
/// Отличие от C (Р1 класс а): при длинах 6/0..6/3 адрес назначения C читает за проверенной частью, и в кадре короче
/// `38 + pl` байт это чтение за краем кадра (`src/proto-preprocess.c:619-621`, `src/stack-arpv4.c:89`); здесь такой
/// кадр запросом не считается. Тотальна: каждое чтение проверено, ничего не выделяет.
pub fn incoming_request(frame: &[u8]) -> Option<IncomingRequest> {
    if frame.len() > crate::receive::MAX_FRAME_LEN || frame.get(12..14)? != [0x08, 0x06] {
        return None;
    }
    let a = frame.get(ETH_LEN..ETH_LEN + 8)?;
    let ht = u16::from_be_bytes([a[0], a[1]]);
    let pt = u16::from_be_bytes([a[2], a[3]]);
    let (hl, pl) = (usize::from(a[4]), usize::from(a[5]));
    let op = u16::from_be_bytes([a[6], a[7]]);
    let addrs = ETH_LEN + 8;
    if frame.len() < addrs + 2 * hl + 2 * pl
        || op != 1
        || (pl != 4 && hl != 6)
        || pt != 0x0800
        || (ht != 1 && ht != 6)
    {
        return None;
    }
    Some(IncomingRequest {
        sender_mac: array_at::<6>(frame, addrs)?,
        sender_ip: be32_at(frame, addrs + hl)?,
        target_ip: be32_at(frame, addrs + 2 * hl + pl)?,
    })
}

/// Ответ на ARP-запрос к одному из наших адресов `first..=last` (`is_my_ip`, `src/stack-src.c:8-18`;
/// `src/main.c:829`, `:878-887`): кадр [`encode_reply`] от `my_mac` с запрошенным адресом к `sender_mac` запроса
/// (не к источнику Ethernet), как `stack_arp_incoming_request` (`src/stack-arpv4.c:331-356`). `None`, если C не
/// ответил бы ([`incoming_request`]) или адрес не наш. Адрес источника, принадлежащий ОС, C не отличает: на запрос
/// отвечают и ядро, и сканер.
pub fn answer_request(
    frame: &[u8],
    my_mac: [u8; 6],
    first: u32,
    last: u32,
) -> Option<[u8; ARP_FRAME_LEN]> {
    let r = incoming_request(frame)?;
    (first..=last)
        .contains(&r.target_ip)
        .then(|| encode_reply(my_mac, r.target_ip, r.sender_mac, r.sender_ip))
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
