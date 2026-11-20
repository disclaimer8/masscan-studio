//! Заморозка публичного API ядра на базе `a275ea9e` (AGPL-3.0, порт masscan © Robert David Graham): проверка без
//! выполнения, только компиляция. Охват: каждый `pub`-элемент файлов, которые меняет план native-рефакторинга
//! (`src/{lib,arp,blackrock,checksum,cookie,massip,ndp,packet,payloads,probe,ranges,ranges6,receive,scan,targets,
//! tcp_frame,throttle}.rs`).
//!
//! Инвентарь на базе (команда из корня `rmasscan/crates/rmasscan-core`), 360 строк:
//!
//! ```sh
//! grep -nE '^\s*pub (fn|const|static|struct|enum|type|trait|use|mod)\b|^\s*pub [a-z_0-9]+:' \
//!   src/{lib,arp,blackrock,checksum,cookie,massip,ndp,packet,payloads,probe,ranges,ranges6,receive,scan,targets,tcp_frame,throttle}.rs
//! ```
//!
//! Каждая строка инвентаря это один блок `// <файл>.rs:<номер строки на базе>` ниже; число блоков по файлу равно
//! числу строк инвентаря по этому файлу (lib 21, arp 24, blackrock 9, checksum 10, cookie 4, massip 27, ndp 30,
//! packet 41, payloads 19, probe 59, ranges 17, ranges6 21, receive 25, scan 14, targets 21, tcp_frame 6,
//! throttle 12: всего 360). Дополнительно: варианты `pub enum` (блоки `// <файл>.rs enum <имя>`), производные и
//! авто-трейты (`traits`).
//!
//! Виды проверок: функции и методы это присваивание указателю с полным типом (обобщённые: с конкретными типами, с
//! `impl Trait`: обёртка с теми же параметрами), поля структур это функции-аксессоры с явными типами (новое поле
//! их не ломает), варианты это конструкторы с типами полей, константы это `const _: T = путь;`. Добавленные поля и
//! варианты проверки пропускают, потому что их могут добавить main и 4c. Файл не правится после записи.
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    clippy::type_complexity,
    clippy::too_many_arguments
)]

use rmasscan_core::{
    arp, blackrock, checksum, config, cookie, massip, ndp, packet, payloads, probe, ranges,
    ranges6, receive, scan, stack, targets, tcp_frame, throttle,
};
use std::ops::ControlFlow;

// ===== lib.rs =====
fn check_lib() {
    // lib.rs:5
    {
        use rmasscan_core::arp as _;
    }
    // lib.rs:6
    {
        use rmasscan_core::banner as _;
    }
    // lib.rs:7
    {
        use rmasscan_core::blackrock as _;
    }
    // lib.rs:8
    {
        use rmasscan_core::checksum as _;
    }
    // lib.rs:9
    {
        use rmasscan_core::config as _;
    }
    // lib.rs:10
    {
        use rmasscan_core::cookie as _;
    }
    // lib.rs:11
    {
        use rmasscan_core::massip as _;
    }
    // lib.rs:12
    {
        use rmasscan_core::ndp as _;
    }
    // lib.rs:13
    {
        use rmasscan_core::packet as _;
    }
    // lib.rs:14
    {
        use rmasscan_core::payloads as _;
    }
    // lib.rs:15
    {
        use rmasscan_core::probe as _;
    }
    // lib.rs:16
    {
        use rmasscan_core::ranges as _;
    }
    // lib.rs:17
    {
        use rmasscan_core::ranges6 as _;
    }
    // lib.rs:18
    {
        use rmasscan_core::receive as _;
    }
    // lib.rs:19
    {
        use rmasscan_core::scan as _;
    }
    // lib.rs:20
    {
        use rmasscan_core::stack as _;
    }
    // lib.rs:21
    {
        use rmasscan_core::targets as _;
    }
    // lib.rs:22
    {
        use rmasscan_core::tcp_frame as _;
    }
    // lib.rs:23
    {
        use rmasscan_core::throttle as _;
    }
    // lib.rs:24
    {
        use rmasscan_core::top_ports as _;
    }
    // lib.rs:29
    {
        const _: &str = rmasscan_core::ORACLE_MASSCAN_VERSION;
    }
}

// ===== arp.rs =====
fn check_arp() {
    // arp.rs:15
    {
        const _: usize = arp::ARP_FRAME_LEN;
    }
    // arp.rs:20
    {
        fn _a(_: &arp::ArpOp) {}
    }
    // arp.rs:26
    {
        fn _a(_: &arp::ArpError) {}
    }
    // arp.rs:45
    {
        fn _a(_: &arp::ArpPacket) {}
    }
    // arp.rs:46
    {
        fn _a(x: &arp::ArpPacket) -> &[u8; 6] {
            &x.eth_src
        }
    }
    // arp.rs:47
    {
        fn _a(x: &arp::ArpPacket) -> &arp::ArpOp {
            &x.op
        }
    }
    // arp.rs:48
    {
        fn _a(x: &arp::ArpPacket) -> &[u8; 6] {
            &x.sender_mac
        }
    }
    // arp.rs:49
    {
        fn _a(x: &arp::ArpPacket) -> &u32 {
            &x.sender_ip
        }
    }
    // arp.rs:50
    {
        fn _a(x: &arp::ArpPacket) -> &[u8; 6] {
            &x.target_mac
        }
    }
    // arp.rs:51
    {
        fn _a(x: &arp::ArpPacket) -> &u32 {
            &x.target_ip
        }
    }
    // arp.rs:63
    {
        let _: fn([u8; 6], u32, u32) -> [u8; arp::ARP_FRAME_LEN] = arp::encode_request;
    }
    // arp.rs:79
    {
        let _: fn([u8; 6], u32, [u8; 6], u32) -> [u8; arp::ARP_FRAME_LEN] = arp::encode_reply;
    }
    // arp.rs:98
    {
        let _: fn(&[u8]) -> Result<arp::ArpPacket, arp::ArpError> = arp::decode;
    }
    // arp.rs:147
    {
        fn _a(_: &arp::IncomingRequest) {}
    }
    // arp.rs:150
    {
        fn _a(x: &arp::IncomingRequest) -> &[u8; 6] {
            &x.sender_mac
        }
    }
    // arp.rs:152
    {
        fn _a(x: &arp::IncomingRequest) -> &u32 {
            &x.sender_ip
        }
    }
    // arp.rs:154
    {
        fn _a(x: &arp::IncomingRequest) -> &u32 {
            &x.target_ip
        }
    }
    // arp.rs:174
    {
        let _: fn(&[u8]) -> Option<arp::IncomingRequest> = arp::incoming_request;
    }
    // arp.rs:204
    {
        let _: fn(&[u8], [u8; 6], u32, u32) -> Option<[u8; arp::ARP_FRAME_LEN]> =
            arp::answer_request;
    }
    // arp.rs:219
    {
        fn _a(_: &arp::PendingResolve) {}
    }
    // arp.rs:227
    {
        let _: fn([u8; 6], u32, u32) -> arp::PendingResolve = arp::PendingResolve::new;
    }
    // arp.rs:236
    {
        let _: fn(&arp::PendingResolve) -> [u8; arp::ARP_FRAME_LEN] =
            arp::PendingResolve::request_frame;
    }
    // arp.rs:240
    {
        let _: fn(&arp::PendingResolve) -> Option<[u8; 6]> = arp::PendingResolve::resolved;
    }
    // arp.rs:249
    {
        let _: fn(&mut arp::PendingResolve, &[u8]) -> Option<[u8; 6]> = arp::PendingResolve::offer;
    }
}

// ===== blackrock.rs =====
fn check_blackrock() {
    // blackrock.rs:9
    {
        const _: [u8; 256] = blackrock::SBOX;
    }
    // blackrock.rs:30
    {
        fn _a(_: &blackrock::BlackRockError) {}
    }
    // blackrock.rs:41
    {
        fn _a(_: &blackrock::BlackRock) {}
    }
    // blackrock.rs:52
    {
        let _: fn(u64, u64, u32) -> Result<blackrock::BlackRock, blackrock::BlackRockError> =
            blackrock::BlackRock::try_new;
    }
    // blackrock.rs:87
    {
        let _: fn(u64, u64, u32) -> blackrock::BlackRock = blackrock::BlackRock::new;
    }
    // blackrock.rs:95
    {
        let _: fn(&blackrock::BlackRock, u64) -> u64 = blackrock::BlackRock::shuffle;
    }
    // blackrock.rs:104
    {
        let _: fn(&blackrock::BlackRock) -> u64 = blackrock::BlackRock::domain;
    }
    // blackrock.rs:119
    {
        let _: fn(&blackrock::BlackRock, u64) -> Option<u64> =
            blackrock::BlackRock::shuffle_bounded;
    }
    // blackrock.rs:134
    {
        let _: fn(&blackrock::BlackRock, u64) -> u64 = blackrock::BlackRock::unshuffle;
    }
}

// ===== checksum.rs =====
fn check_checksum() {
    // checksum.rs:36
    {
        let _: fn(&[u8], usize, usize) -> u16 = checksum::ip_header_checksum;
    }
    // checksum.rs:56
    {
        let _: fn(u64) -> u16 = checksum::fold;
    }
    // checksum.rs:68
    {
        let _: fn(&[u8], usize, usize, usize) -> u16 = checksum::tcp_ipv4_partial;
    }
    // checksum.rs:84
    {
        let _: fn(&[u8]) -> u64 = checksum::word_sum;
    }
    // checksum.rs:109
    {
        let _: fn(u32, u32, &[u8]) -> u16 = checksum::udp_ipv4_checksum;
    }
    // checksum.rs:119
    {
        let _: fn(u32, u32, &[u8]) -> bool = checksum::udp_ipv4_checksum_ok;
    }
    // checksum.rs:153
    {
        let _: fn(&[u8]) -> u32 = checksum::sctp_crc32c;
    }
    // checksum.rs:169
    {
        let _: fn(u32) -> u16 = checksum::fold_and_invert;
    }
    // checksum.rs:182
    {
        let _: fn(u32, u32, u8, &[u8]) -> u16 = checksum::checksum_ipv4;
    }
    // checksum.rs:213
    {
        let _: fn(u128, u128, u8, &[u8]) -> u16 = checksum::checksum_ipv6;
    }
}

// ===== cookie.rs =====
fn check_cookie() {
    // cookie.rs:11
    {
        let _: fn(&[u8], u64, u64) -> u64 = cookie::siphash24;
    }
    // cookie.rs:18
    {
        let _: fn(u32, u32, u32, u32, u64) -> u64 = cookie::syn_cookie_ipv4;
    }
    // cookie.rs:46
    {
        let _: fn(u128, u32, u128, u32, u64) -> u64 = cookie::syn_cookie_ipv6;
    }
    // cookie.rs:66
    {
        let _: fn(u32, u32, u64) -> u32 = cookie::icmp_echo_cookie;
    }
}

// ===== massip.rs =====
fn check_massip() {
    // massip.rs:31
    {
        fn _a(_: &massip::RangeOverflow) {}
    }
    // massip.rs:32
    {
        fn _a(x: &massip::RangeOverflow) -> &u32 {
            &x.bits
        }
    }
    // massip.rs:38
    {
        fn _a(_: &massip::TargetIp) {}
    }
    // massip.rs:50
    {
        fn _a(_: &massip::MassIp) {}
    }
    // massip.rs:65
    {
        let _: fn() -> massip::MassIp = massip::MassIp::new;
    }
    // massip.rs:69
    {
        let _: fn(&massip::MassIp) -> &ranges::RangeList = massip::MassIp::ipv4;
    }
    // massip.rs:73
    {
        let _: fn(&massip::MassIp) -> &ranges6::Range6List = massip::MassIp::ipv6;
    }
    // massip.rs:77
    {
        let _: fn(&massip::MassIp) -> &ranges::RangeList = massip::MassIp::ports;
    }
    // massip.rs:82
    {
        let _: fn(&mut massip::MassIp) -> &mut ranges6::Range6List = massip::MassIp::ipv6_mut;
    }
    // massip.rs:89
    {
        let _: fn(&mut massip::MassIp, &str) -> Result<(), targets::ParseError> =
            massip::MassIp::add_target_string;
    }
    // massip.rs:95
    {
        let _: fn(&mut massip::MassIp) -> &mut ranges::RangeList = massip::MassIp::ipv4_mut;
    }
    // massip.rs:102
    {
        let _: fn(&mut massip::MassIp) -> &mut ranges::RangeList = massip::MassIp::ports_mut;
    }
    // massip.rs:109
    {
        let _: fn(&mut massip::MassIp, &mut massip::MassIp) -> () = massip::MassIp::apply_excludes;
    }
    // massip.rs:119
    {
        let _: fn(&mut massip::MassIp) -> () = massip::MassIp::optimize;
    }
    // massip.rs:130
    {
        let _: fn(&massip::MassIp) -> u64 = massip::MassIp::count_ports;
    }
    // massip.rs:134
    {
        let _: fn(&massip::MassIp) -> u64 = massip::MassIp::count_ipv4s;
    }
    // massip.rs:140
    {
        let _: fn(&massip::MassIp) -> u64 = massip::MassIp::count_ipv6s;
    }
    // massip.rs:145
    {
        let _: fn(&massip::MassIp) -> bool = massip::MassIp::has_ipv6_targets;
    }
    // massip.rs:161
    {
        let _: fn(&massip::MassIp) -> Result<u64, massip::RangeOverflow> =
            massip::MassIp::try_range;
    }
    // massip.rs:186
    {
        let _: fn(&massip::MassIp) -> u64 = massip::MassIp::range_ipv6;
    }
    // massip.rs:193
    {
        let _: fn(&massip::MassIp) -> u64 = massip::MassIp::range;
    }
    // massip.rs:208
    {
        let _: fn(&massip::MassIp, u64) -> (u32, u32) = massip::MassIp::pick;
    }
    // massip.rs:226
    {
        let _: fn(&massip::MassIp, u64) -> (massip::TargetIp, u32) = massip::MassIp::pick_list;
    }
    // massip.rs:249
    {
        let _: fn(&massip::MassIp, u64) -> (massip::TargetIp, u32, u64) =
            massip::MassIp::pick_transmit;
    }
    // massip.rs:263
    {
        let _: fn(&massip::MassIp, u32) -> bool = massip::MassIp::has_ip;
    }
    // massip.rs:268
    {
        let _: fn(&massip::MassIp, u128) -> bool = massip::MassIp::has_ip6;
    }
    // massip.rs:273
    {
        let _: fn(&massip::MassIp, u32) -> bool = massip::MassIp::has_port;
    }
}

// ===== ndp.rs =====
fn check_ndp() {
    // ndp.rs:27
    {
        const _: usize = ndp::NDP_FRAME_LEN;
    }
    // ndp.rs:34
    {
        const _: u8 = ndp::NEIGHBOR_SOLICITATION;
    }
    // ndp.rs:36
    {
        const _: u8 = ndp::NEIGHBOR_ADVERTISEMENT;
    }
    // ndp.rs:41
    {
        const _: u8 = ndp::NA_FLAGS_SOLICITED_OVERRIDE;
    }
    // ndp.rs:45
    {
        let _: fn(u128) -> u128 = ndp::solicited_node_address;
    }
    // ndp.rs:50
    {
        let _: fn(u128) -> [u8; 6] = ndp::solicited_node_mac;
    }
    // ndp.rs:109
    {
        let _: fn([u8; 6], u128, u128) -> [u8; ndp::NDP_FRAME_LEN] =
            ndp::encode_neighbor_solicitation;
    }
    // ndp.rs:129
    {
        let _: fn([u8; 6], u128, [u8; 6], u128) -> [u8; ndp::NDP_FRAME_LEN] =
            ndp::encode_neighbor_advertisement;
    }
    // ndp.rs:149
    {
        fn _a(_: &ndp::NdpError) {}
    }
    // ndp.rs:249
    {
        fn _a(_: &ndp::NeighborAdvertisement) {}
    }
    // ndp.rs:250
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &[u8; 6] {
            &x.eth_dst
        }
    }
    // ndp.rs:251
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &[u8; 6] {
            &x.eth_src
        }
    }
    // ndp.rs:252
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &u128 {
            &x.src_ip
        }
    }
    // ndp.rs:253
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &u128 {
            &x.dst_ip
        }
    }
    // ndp.rs:254
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &u8 {
            &x.flags
        }
    }
    // ndp.rs:255
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &u128 {
            &x.target
        }
    }
    // ndp.rs:257
    {
        fn _a(x: &ndp::NeighborAdvertisement) -> &[u8; 6] {
            &x.target_lla
        }
    }
    // ndp.rs:263
    {
        let _: fn(&[u8]) -> Result<ndp::NeighborAdvertisement, ndp::NdpError> =
            ndp::decode_neighbor_advertisement;
    }
    // ndp.rs:287
    {
        fn _a(_: &ndp::NeighborSolicitation) {}
    }
    // ndp.rs:288
    {
        fn _a(x: &ndp::NeighborSolicitation) -> &[u8; 6] {
            &x.eth_src
        }
    }
    // ndp.rs:289
    {
        fn _a(x: &ndp::NeighborSolicitation) -> &u128 {
            &x.src_ip
        }
    }
    // ndp.rs:290
    {
        fn _a(x: &ndp::NeighborSolicitation) -> &u128 {
            &x.dst_ip
        }
    }
    // ndp.rs:291
    {
        fn _a(x: &ndp::NeighborSolicitation) -> &u128 {
            &x.target
        }
    }
    // ndp.rs:296
    {
        let _: fn(&[u8]) -> Result<ndp::NeighborSolicitation, ndp::NdpError> =
            ndp::decode_neighbor_solicitation;
    }
    // ndp.rs:317
    {
        let _: fn(&[u8], [u8; 6], u128) -> Option<[u8; ndp::NDP_FRAME_LEN]> =
            ndp::answer_neighbor_solicitation;
    }
    // ndp.rs:339
    {
        fn _a(_: &ndp::PendingNdp) {}
    }
    // ndp.rs:347
    {
        let _: fn([u8; 6], u128, u128) -> ndp::PendingNdp = ndp::PendingNdp::new;
    }
    // ndp.rs:357
    {
        let _: fn(&ndp::PendingNdp) -> [u8; ndp::NDP_FRAME_LEN] = ndp::PendingNdp::request_frame;
    }
    // ndp.rs:363
    {
        let _: fn(&mut ndp::PendingNdp, &[u8]) -> Option<[u8; 6]> = ndp::PendingNdp::offer;
    }
    // ndp.rs:375
    {
        let _: fn(&ndp::PendingNdp) -> Option<[u8; 6]> = ndp::PendingNdp::resolved;
    }
}

// ===== packet.rs =====
fn check_packet() {
    // packet.rs:17
    {
        fn _a(_: &packet::LinkType) {}
    }
    // packet.rs:25
    {
        const _: &[u8] = packet::DEFAULT_TCP_TEMPLATE;
    }
    // packet.rs:37
    {
        const _: u16 = packet::DEFAULT_TCP_MSS;
    }
    // packet.rs:39
    {
        const _: u8 = packet::DEFAULT_TCP_WSCALE;
    }
    // packet.rs:41
    {
        const _: u32 = packet::DEFAULT_TCP_TSECHO;
    }
    // packet.rs:47
    {
        fn _a(_: &packet::TcpHeaderOptions) {}
    }
    // packet.rs:48
    {
        fn _a(x: &packet::TcpHeaderOptions) -> &Option<u16> {
            &x.mss
        }
    }
    // packet.rs:49
    {
        fn _a(x: &packet::TcpHeaderOptions) -> &bool {
            &x.sackok
        }
    }
    // packet.rs:50
    {
        fn _a(x: &packet::TcpHeaderOptions) -> &Option<u8> {
            &x.wscale
        }
    }
    // packet.rs:51
    {
        fn _a(x: &packet::TcpHeaderOptions) -> &Option<u32> {
            &x.tsecho
        }
    }
    // packet.rs:68
    {
        fn _a(_: &packet::PacketModifiers) {}
    }
    // packet.rs:69
    {
        fn _a(x: &packet::PacketModifiers) -> &u8 {
            &x.ttl
        }
    }
    // packet.rs:70
    {
        fn _a(x: &packet::PacketModifiers) -> &bool {
            &x.badsum
        }
    }
    // packet.rs:71
    {
        fn _a(x: &packet::PacketModifiers) -> &packet::TcpHeaderOptions {
            &x.tcp
        }
    }
    // packet.rs:124
    {
        fn _a(_: &packet::TcpSynTemplate) {}
    }
    // packet.rs:142
    {
        let _: fn([u8; 6], [u8; 6], packet::LinkType) -> packet::TcpSynTemplate =
            packet::TcpSynTemplate::new;
    }
    // packet.rs:149
    {
        let _: fn(
            [u8; 6],
            [u8; 6],
            packet::LinkType,
            &packet::PacketModifiers,
        ) -> packet::TcpSynTemplate = packet::TcpSynTemplate::new_with_options;
    }
    // packet.rs:205
    {
        let _: fn(&packet::TcpSynTemplate) -> bool = packet::TcpSynTemplate::proto_is_tcp;
    }
    // packet.rs:210
    {
        let _: fn(&packet::TcpSynTemplate) -> u16 = packet::TcpSynTemplate::checksum_ip;
    }
    // packet.rs:223
    {
        let _: fn(&packet::TcpSynTemplate, u32, u16, u32, u16, u32, &mut Vec<u8>) -> () =
            packet::TcpSynTemplate::build_syn;
    }
    // packet.rs:309
    {
        fn _a(_: &packet::Tcp6SynTemplate) {}
    }
    // packet.rs:318
    {
        let _: fn([u8; 6], [u8; 6], packet::LinkType) -> packet::Tcp6SynTemplate =
            packet::Tcp6SynTemplate::new;
    }
    // packet.rs:328
    {
        let _: fn(
            [u8; 6],
            [u8; 6],
            packet::LinkType,
            &packet::PacketModifiers,
        ) -> packet::Tcp6SynTemplate = packet::Tcp6SynTemplate::new_with_options;
    }
    // packet.rs:372
    {
        let _: fn(&packet::Tcp6SynTemplate) -> bool = packet::Tcp6SynTemplate::proto_is_tcp;
    }
    // packet.rs:385
    {
        let _: fn(&packet::Tcp6SynTemplate, u128, u16, u128, u16, u32, &mut Vec<u8>) -> () =
            packet::Tcp6SynTemplate::build_syn;
    }
    // packet.rs:416
    {
        const _: &[u8] = packet::DEFAULT_ICMP_PING_TEMPLATE;
    }
    // packet.rs:430
    {
        fn _a(_: &packet::IcmpEchoTemplate) {}
    }
    // packet.rs:441
    {
        let _: fn([u8; 6], [u8; 6], packet::LinkType, u8) -> packet::IcmpEchoTemplate =
            packet::IcmpEchoTemplate::new;
    }
    // packet.rs:474
    {
        let _: fn(&packet::IcmpEchoTemplate, u32, u32, u32, u64, &mut Vec<u8>) -> () =
            packet::IcmpEchoTemplate::build_echo;
    }
    // packet.rs:506
    {
        const _: &[u8] = packet::DEFAULT_UDP_TEMPLATE;
    }
    // packet.rs:518
    {
        fn _a(_: &packet::UdpTemplate) {}
    }
    // packet.rs:527
    {
        let _: fn([u8; 6], [u8; 6], packet::LinkType, u8) -> packet::UdpTemplate =
            packet::UdpTemplate::new;
    }
    // packet.rs:559
    {
        let _: fn(
            &packet::UdpTemplate,
            (u32, u16),
            (u32, u16),
            u32,
            Option<&payloads::PayloadEntry>,
            &mut Vec<u8>,
        ) -> () = packet::UdpTemplate::build_udp;
    }
    // packet.rs:597
    {
        const _: &[u8] = packet::DEFAULT_SCTP_INIT_TEMPLATE;
    }
    // packet.rs:611
    {
        fn _a(_: &packet::SctpTemplate) {}
    }
    // packet.rs:620
    {
        let _: fn([u8; 6], [u8; 6], packet::LinkType, u8) -> packet::SctpTemplate =
            packet::SctpTemplate::new;
    }
    // packet.rs:652
    {
        let _: fn(&packet::SctpTemplate, (u32, u16), (u32, u16), u32, &mut Vec<u8>) -> () =
            packet::SctpTemplate::build_init;
    }
    // packet.rs:682
    {
        const _: &[u8] = packet::DEFAULT_ARP_TEMPLATE;
    }
    // packet.rs:697
    {
        fn _a(_: &packet::ArpTemplate) {}
    }
    // packet.rs:703
    {
        let _: fn([u8; 6]) -> packet::ArpTemplate = packet::ArpTemplate::new;
    }
    // packet.rs:713
    {
        let _: fn(&packet::ArpTemplate, u32, u32, &mut Vec<u8>) -> () =
            packet::ArpTemplate::build_arp;
    }
}

// ===== payloads.rs =====
fn check_payloads() {
    // payloads.rs:26
    {
        const _: usize = payloads::MAX_PAYLOAD_LEN;
    }
    // payloads.rs:34
    {
        fn _a(_: &payloads::CookieMutator) {}
    }
    // payloads.rs:51
    {
        let _: fn(payloads::CookieMutator, &mut [u8], u32) -> () = payloads::CookieMutator::apply;
    }
    // payloads.rs:746
    {
        fn _a(_: &payloads::PayloadEntry) {}
    }
    // payloads.rs:748
    {
        fn _a(x: &payloads::PayloadEntry) -> &std::sync::Arc<[u8]> {
            &x.payload
        }
    }
    // payloads.rs:750
    {
        fn _a(x: &payloads::PayloadEntry) -> &u32 {
            &x.source_port
        }
    }
    // payloads.rs:753
    {
        fn _a(x: &payloads::PayloadEntry) -> &Option<payloads::CookieMutator> {
            &x.set_cookie
        }
    }
    // payloads.rs:758
    {
        let _: fn(&payloads::PayloadEntry, u32) -> Vec<u8> = payloads::PayloadEntry::with_cookie;
    }
    // payloads.rs:769
    {
        fn _a(_: &payloads::PayloadError) {}
    }
    // payloads.rs:783
    {
        fn _a(_: &payloads::PayloadTable) {}
    }
    // payloads.rs:795
    {
        let _: fn() -> payloads::PayloadTable = payloads::PayloadTable::empty;
    }
    // payloads.rs:802
    {
        let _: fn() -> payloads::PayloadTable = payloads::PayloadTable::builtin;
    }
    // payloads.rs:828
    {
        let _: fn(&payloads::PayloadTable, u16) -> Option<&payloads::PayloadEntry> =
            payloads::PayloadTable::get;
    }
    // payloads.rs:833
    {
        let _: fn(&payloads::PayloadTable) -> usize = payloads::PayloadTable::len;
    }
    // payloads.rs:837
    {
        let _: fn(&payloads::PayloadTable) -> bool = payloads::PayloadTable::is_empty;
    }
    // payloads.rs:842
    {
        fn _a(t: &payloads::PayloadTable) -> impl Iterator<Item = u32> + '_ {
            t.ports()
        }
    }
    // payloads.rs:881
    {
        let _: fn(&mut payloads::PayloadTable, &str) -> Result<usize, payloads::PayloadError> =
            payloads::PayloadTable::load_nmap_payloads;
    }
    // payloads.rs:886
    {
        let _: fn(&mut payloads::PayloadTable, &[u8]) -> Result<usize, payloads::PayloadError> =
            payloads::PayloadTable::load_nmap_payloads_bytes;
    }
    // payloads.rs:948
    {
        let _: fn(&mut payloads::PayloadTable, &[u8]) -> Result<usize, payloads::PayloadError> =
            payloads::PayloadTable::load_pcap_payloads;
    }
}

// ===== probe.rs =====
fn check_probe() {
    // probe.rs:26
    {
        fn _a(t: massip::TargetIp) -> probe::TargetIp {
            t
        }
        fn _b(t: probe::TargetIp) -> massip::TargetIp {
            t
        }
    }
    // probe.rs:42
    {
        const _: u32 = probe::RUNTIME_BLACKROCK_ROUNDS;
    }
    // probe.rs:46
    {
        fn _a(_: &probe::PlanError) {}
    }
    // probe.rs:139
    {
        fn _a(_: &probe::AdapterBinding) {}
    }
    // probe.rs:140
    {
        fn _a(x: &probe::AdapterBinding) -> &String {
            &x.interface_id
        }
    }
    // probe.rs:141
    {
        fn _a(x: &probe::AdapterBinding) -> &packet::LinkType {
            &x.link_type
        }
    }
    // probe.rs:142
    {
        fn _a(x: &probe::AdapterBinding) -> &u32 {
            &x.source_ipv4
        }
    }
    // probe.rs:143
    {
        fn _a(x: &probe::AdapterBinding) -> &[u8; 6] {
            &x.source_mac
        }
    }
    // probe.rs:144
    {
        fn _a(x: &probe::AdapterBinding) -> &[u8; 6] {
            &x.next_hop_mac
        }
    }
    // probe.rs:146
    {
        fn _a(x: &probe::AdapterBinding) -> &(u16, u16) {
            &x.source_ports
        }
    }
    // probe.rs:153
    {
        fn _a(_: &probe::NicBinding) {}
    }
    // probe.rs:154
    {
        fn _a(x: &probe::NicBinding) -> &probe::AdapterBinding {
            &x.binding
        }
    }
    // probe.rs:157
    {
        fn _a(x: &probe::NicBinding) -> &u32 {
            &x.source_ipv4_last
        }
    }
    // probe.rs:162
    {
        fn _a(x: &probe::NicBinding) -> &bool {
            &x.legacy_c_17_port_mask
        }
    }
    // probe.rs:167
    {
        fn _a(x: &probe::NicBinding) -> &Option<u128> {
            &x.source_ipv6
        }
    }
    // probe.rs:172
    {
        fn _a(x: &probe::NicBinding) -> &Option<[u8; 6]> {
            &x.next_hop_mac_ipv6
        }
    }
    // probe.rs:189
    {
        fn _a(_: &probe::Probe) {}
    }
    // probe.rs:192
    {
        fn _a(x: &probe::Probe) -> &u64 {
            &x.index
        }
    }
    // probe.rs:193
    {
        fn _a(x: &probe::Probe) -> &u32 {
            &x.ip_me
        }
    }
    // probe.rs:194
    {
        fn _a(x: &probe::Probe) -> &u16 {
            &x.port_me
        }
    }
    // probe.rs:195
    {
        fn _a(x: &probe::Probe) -> &u32 {
            &x.ip_them
        }
    }
    // probe.rs:199
    {
        fn _a(x: &probe::Probe) -> &massip::TargetIp {
            &x.target
        }
    }
    // probe.rs:200
    {
        fn _a(x: &probe::Probe) -> &u16 {
            &x.port_them
        }
    }
    // probe.rs:203
    {
        fn _a(x: &probe::Probe) -> &u32 {
            &x.port_index
        }
    }
    // probe.rs:204
    {
        fn _a(x: &probe::Probe) -> &u32 {
            &x.seqno
        }
    }
    // probe.rs:205
    {
        fn _a(x: &probe::Probe) -> &Vec<u8> {
            &x.frame
        }
    }
    // probe.rs:477
    {
        fn _a<B>(
            eff: &config::EffectiveConfig,
            binding: &probe::AdapterBinding,
            f: impl FnMut(&probe::Probe) -> ControlFlow<B>,
        ) -> Result<ControlFlow<B>, probe::PlanError> {
            probe::for_each_probe(eff, binding, f)
        }
    }
    // probe.rs:491
    {
        fn _a<B>(
            eff: &config::EffectiveConfig,
            nic: &probe::NicBinding,
            f: impl FnMut(&probe::Probe) -> ControlFlow<B>,
        ) -> Result<ControlFlow<B>, probe::PlanError> {
            probe::for_each_probe_nic(eff, nic, f)
        }
    }
    // probe.rs:500
    {
        fn _a<B>(
            eff: &config::EffectiveConfig,
            nic: &probe::NicBinding,
            payloads: &payloads::PayloadTable,
            f: impl FnMut(&probe::Probe) -> ControlFlow<B>,
        ) -> Result<ControlFlow<B>, probe::PlanError> {
            probe::for_each_probe_nic_with_payloads(eff, nic, payloads, f)
        }
    }
    // probe.rs:568
    {
        let _: fn(&ranges::RangeList) -> Result<(), probe::PlanError> = probe::check_cli_ports;
    }
    // probe.rs:597
    {
        let _: fn(&ranges::RangeList) -> bool = probe::is_arp_scan_ports;
    }
    // probe.rs:604
    {
        fn _a(_: &probe::ReadyPlan) {}
    }
    // probe.rs:609
    {
        let _: fn(
            config::EffectiveConfig,
            probe::AdapterBinding,
        ) -> Result<probe::ReadyPlan, probe::PlanError> = probe::ReadyPlan::new;
    }
    // probe.rs:619
    {
        let _: fn(
            config::EffectiveConfig,
            probe::AdapterBinding,
            std::collections::BTreeMap<u32, [u8; 6]>,
        ) -> Result<probe::ReadyPlan, probe::PlanError> = probe::ReadyPlan::with_destinations;
    }
    // probe.rs:691
    {
        let _: fn(
            config::EffectiveConfig,
            Vec<probe::NicBinding>,
        ) -> Result<probe::ReadyPlan, probe::PlanError> = probe::ReadyPlan::new_cli;
    }
    // probe.rs:700
    {
        let _: fn(
            config::EffectiveConfig,
            Vec<probe::NicBinding>,
            payloads::PayloadTable,
        ) -> Result<probe::ReadyPlan, probe::PlanError> = probe::ReadyPlan::new_cli_with_payloads;
    }
    // probe.rs:711
    {
        let _: fn(
            config::EffectiveConfig,
            Vec<probe::NicBinding>,
        ) -> Result<probe::ReadyPlan, probe::PlanError> =
            probe::ReadyPlan::new_cli_without_port_checks;
    }
    // probe.rs:825
    {
        let _: fn(&probe::ReadyPlan) -> &config::EffectiveConfig = probe::ReadyPlan::effective;
    }
    // probe.rs:831
    {
        let _: fn(&probe::ReadyPlan) -> bool = probe::ReadyPlan::is_arp_scan;
    }
    // probe.rs:836
    {
        let _: fn(&probe::ReadyPlan) -> &payloads::PayloadTable = probe::ReadyPlan::payloads;
    }
    // probe.rs:841
    {
        let _: fn(&probe::ReadyPlan) -> &probe::AdapterBinding = probe::ReadyPlan::binding;
    }
    // probe.rs:846
    {
        let _: fn(&probe::ReadyPlan) -> &[probe::NicBinding] = probe::ReadyPlan::nics;
    }
    // probe.rs:851
    {
        let _: fn(&probe::ReadyPlan) -> Option<&std::collections::BTreeMap<u32, [u8; 6]>> =
            probe::ReadyPlan::destinations;
    }
    // probe.rs:858
    {
        let _: fn(
            &probe::ReadyPlan,
            usize,
            u64,
            u128,
            u32,
        ) -> Result<probe::Probe, probe::PlanError> = probe::ReadyPlan::probe_v6;
    }
    // probe.rs:879
    {
        let _: fn(&probe::ReadyPlan) -> u64 = probe::ReadyPlan::range;
    }
    // probe.rs:885
    {
        let _: fn(&probe::ReadyPlan, u32) -> u64 = probe::ReadyPlan::nic_offset;
    }
    // probe.rs:894
    {
        let _: fn(&probe::ReadyPlan, u32) -> u64 = probe::ReadyPlan::effective_end;
    }
    // probe.rs:917
    {
        let _: fn(
            &probe::ReadyPlan,
            u32,
            Option<u64>,
        ) -> Result<probe::ProbeCursor, probe::PlanError> = probe::ReadyPlan::cursor_for_nic;
    }
    // probe.rs:974
    {
        fn _a(_: &probe::ProbeCursor) {}
    }
    // probe.rs:1010
    {
        let _: fn(&probe::ReadyPlan, u64) -> Result<probe::ProbeCursor, probe::PlanError> =
            probe::ProbeCursor::new;
    }
    // probe.rs:1017
    {
        let _: fn(&probe::ProbeCursor) -> u64 = probe::ProbeCursor::resume_base;
    }
    // probe.rs:1078
    {
        let _: fn(&probe::ProbeCursor) -> Option<probe::PlanError> =
            probe::ProbeCursor::build_error;
    }
    // probe.rs:1085
    {
        let _: fn(&probe::ProbeCursor) -> u64 = probe::ProbeCursor::repeats;
    }
    // probe.rs:1098
    {
        let _: fn(&mut probe::ProbeCursor) -> bool = probe::ProbeCursor::advance_pass;
    }
    // probe.rs:1152
    {
        let _: fn(&mut probe::ProbeCursor) -> Option<&probe::Probe> = probe::ProbeCursor::current;
    }
    // probe.rs:1163
    {
        let _: fn(&mut probe::ProbeCursor, usize) -> &[probe::Probe] = probe::ProbeCursor::preload;
    }
    // probe.rs:1171
    {
        let _: fn(&mut probe::ProbeCursor) -> () = probe::ProbeCursor::advance_sent;
    }
    // probe.rs:1180
    {
        let _: fn(&mut probe::ProbeCursor, usize) -> () = probe::ProbeCursor::advance_sent_n;
    }
    // probe.rs:1192
    {
        let _: fn(&probe::ProbeCursor) -> u64 = probe::ProbeCursor::position;
    }
}

// ===== ranges.rs =====
fn check_ranges() {
    // ranges.rs:10
    {
        fn _a(_: &ranges::Range) {}
    }
    // ranges.rs:11
    {
        fn _a(x: &ranges::Range) -> &u32 {
            &x.begin
        }
    }
    // ranges.rs:12
    {
        fn _a(x: &ranges::Range) -> &u32 {
            &x.end
        }
    }
    // ranges.rs:86
    {
        fn _a(_: &ranges::RangeList) {}
    }
    // ranges.rs:100
    {
        let _: fn() -> ranges::RangeList = ranges::RangeList::new;
    }
    // ranges.rs:109
    {
        let _: fn(&ranges::RangeList) -> usize = ranges::RangeList::len;
    }
    // ranges.rs:113
    {
        let _: fn(&ranges::RangeList) -> bool = ranges::RangeList::is_empty;
    }
    // ranges.rs:117
    {
        let _: fn(&ranges::RangeList, usize) -> ranges::Range = ranges::RangeList::get;
    }
    // ranges.rs:121
    {
        let _: fn(&ranges::RangeList) -> &[ranges::Range] = ranges::RangeList::as_slice;
    }
    // ranges.rs:128
    {
        let _: fn(&mut ranges::RangeList, u32, u32) -> () = ranges::RangeList::add_range;
    }
    // ranges.rs:146
    {
        let _: fn(&mut ranges::RangeList) -> () = ranges::RangeList::sort_and_merge;
    }
    // ranges.rs:164
    {
        let _: fn(&ranges::RangeList, u32) -> bool = ranges::RangeList::is_contains;
    }
    // ranges.rs:169
    {
        let _: fn(&ranges::RangeList) -> u64 = ranges::RangeList::count;
    }
    // ranges.rs:182
    {
        let _: fn(&mut ranges::RangeList) -> () = ranges::RangeList::optimize;
    }
    // ranges.rs:217
    {
        let _: fn(&ranges::RangeList, u64) -> u32 = ranges::RangeList::pick;
    }
    // ranges.rs:242
    {
        let _: fn(&mut ranges::RangeList, &mut ranges::RangeList) -> () =
            ranges::RangeList::exclude;
    }
    // ranges.rs:298
    {
        let _: fn(ranges::Range) -> Option<u32> = ranges::range_is_cidr;
    }
}

// ===== ranges6.rs =====
fn check_ranges6() {
    // ranges6.rs:15
    {
        fn _a(x: &ranges6::Ipv6AddrBytes) -> &[u8; 16] {
            &x.0
        }
    }
    // ranges6.rs:18
    {
        let _: fn(u128) -> ranges6::Ipv6AddrBytes = ranges6::Ipv6AddrBytes::from_u128;
    }
    // ranges6.rs:22
    {
        let _: fn(ranges6::Ipv6AddrBytes) -> u128 = ranges6::Ipv6AddrBytes::to_u128;
    }
    // ranges6.rs:35
    {
        fn _a(_: &ranges6::Ipv6Range) {}
    }
    // ranges6.rs:36
    {
        fn _a(x: &ranges6::Ipv6Range) -> &u128 {
            &x.begin
        }
    }
    // ranges6.rs:37
    {
        fn _a(x: &ranges6::Ipv6Range) -> &u128 {
            &x.end
        }
    }
    // ranges6.rs:60
    {
        fn _a(_: &ranges6::Range6List) {}
    }
    // ranges6.rs:75
    {
        let _: fn() -> ranges6::Range6List = ranges6::Range6List::new;
    }
    // ranges6.rs:84
    {
        let _: fn(&ranges6::Range6List) -> usize = ranges6::Range6List::len;
    }
    // ranges6.rs:88
    {
        let _: fn(&ranges6::Range6List) -> bool = ranges6::Range6List::is_empty;
    }
    // ranges6.rs:92
    {
        let _: fn(&ranges6::Range6List, usize) -> ranges6::Ipv6Range = ranges6::Range6List::get;
    }
    // ranges6.rs:96
    {
        let _: fn(&ranges6::Range6List) -> &[ranges6::Ipv6Range] = ranges6::Range6List::as_slice;
    }
    // ranges6.rs:104
    {
        let _: fn(&mut ranges6::Range6List, u128, u128) -> () = ranges6::Range6List::add;
    }
    // ranges6.rs:128
    {
        let _: fn(&mut ranges6::Range6List) -> () = ranges6::Range6List::sort_and_merge;
    }
    // ranges6.rs:146
    {
        let _: fn(&ranges6::Range6List, u128) -> bool = ranges6::Range6List::is_contains;
    }
    // ranges6.rs:154
    {
        let _: fn(&ranges6::Range6List) -> u128 = ranges6::Range6List::count_u128;
    }
    // ranges6.rs:168
    {
        let _: fn(&mut ranges6::Range6List) -> () = ranges6::Range6List::optimize;
    }
    // ranges6.rs:190
    {
        let _: fn(&ranges6::Range6List, u64) -> u128 = ranges6::Range6List::pick;
    }
    // ranges6.rs:266
    {
        let _: fn(&mut ranges6::Range6List, &ranges6::Range6List) -> u128 =
            ranges6::Range6List::apply_excludes;
    }
    // ranges6.rs:280
    {
        let _: fn(u128) -> String = ranges6::format_ipv6_c;
    }
    // ranges6.rs:617
    {
        let _: fn(&str) -> Result<ranges6::Ipv6Range, targets::ParseError> =
            ranges6::parse_ipv6_target;
    }
}

// ===== receive.rs =====
fn check_receive() {
    // receive.rs:52
    {
        const _: usize = receive::MAX_FRAME_LEN;
    }
    // receive.rs:60
    {
        fn _a(_: &receive::ChecksumPolicy) {}
    }
    // receive.rs:72
    {
        fn _a(_: &receive::Unsupported) {}
    }
    // receive.rs:79
    {
        fn _a(_: &receive::ParseError) {}
    }
    // receive.rs:120
    {
        fn _a(_: &receive::PortStatus) {}
    }
    // receive.rs:131
    {
        fn _a(_: &receive::ReplyIpv6) {}
    }
    // receive.rs:133
    {
        fn _a(x: &receive::ReplyIpv6) -> &u128 {
            &x.remote
        }
    }
    // receive.rs:135
    {
        fn _a(x: &receive::ReplyIpv6) -> &u128 {
            &x.local
        }
    }
    // receive.rs:140
    {
        fn _a(_: &receive::Reply) {}
    }
    // receive.rs:141
    {
        fn _a(x: &receive::Reply) -> &u32 {
            &x.remote_ip
        }
    }
    // receive.rs:142
    {
        fn _a(x: &receive::Reply) -> &u16 {
            &x.remote_port
        }
    }
    // receive.rs:143
    {
        fn _a(x: &receive::Reply) -> &u32 {
            &x.local_ip
        }
    }
    // receive.rs:144
    {
        fn _a(x: &receive::Reply) -> &u16 {
            &x.local_port
        }
    }
    // receive.rs:145
    {
        fn _a(x: &receive::Reply) -> &receive::PortStatus {
            &x.status
        }
    }
    // receive.rs:147
    {
        fn _a(x: &receive::Reply) -> &u8 {
            &x.tcp_flags
        }
    }
    // receive.rs:148
    {
        fn _a(x: &receive::Reply) -> &u8 {
            &x.ttl
        }
    }
    // receive.rs:151
    {
        fn _a(x: &receive::Reply) -> &u8 {
            &x.ip_proto
        }
    }
    // receive.rs:153
    {
        fn _a(x: &receive::Reply) -> &Option<[u8; 6]> {
            &x.mac
        }
    }
    // receive.rs:157
    {
        fn _a(x: &receive::Reply) -> &Option<receive::ReplyIpv6> {
            &x.ip6
        }
    }
    // receive.rs:161
    {
        let _: fn(u32) -> Result<packet::LinkType, receive::ParseError> =
            receive::link_type_from_dlt;
    }
    // receive.rs:184
    {
        let _: fn(
            &[u8],
            packet::LinkType,
            &probe::ReadyPlan,
        ) -> Result<Option<receive::Reply>, receive::ParseError> = receive::parse_reply;
    }
    // receive.rs:193
    {
        let _: fn(
            &[u8],
            packet::LinkType,
            &probe::ReadyPlan,
            receive::ChecksumPolicy,
        ) -> Result<Option<receive::Reply>, receive::ParseError> = receive::parse_reply_with;
    }
    // receive.rs:231
    {
        let _: fn(&[u8], packet::LinkType) -> Option<&[u8]> = receive::udp_payload;
    }
    // receive.rs:265
    {
        let _: fn(&[u8], packet::LinkType, &probe::ReadyPlan) -> Option<[u8; ndp::NDP_FRAME_LEN]> =
            receive::ndp_reply_for;
    }
    // receive.rs:283
    {
        let _: fn(&[u8], packet::LinkType, &probe::ReadyPlan) -> Option<[u8; arp::ARP_FRAME_LEN]> =
            receive::arp_reply_for;
    }
}

// ===== scan.rs =====
fn check_scan() {
    // scan.rs:21
    {
        fn _a(_: &scan::Shard) {}
    }
    // scan.rs:22
    {
        fn _a(x: &scan::Shard) -> &u32 {
            &x.one
        }
    }
    // scan.rs:23
    {
        fn _a(x: &scan::Shard) -> &u32 {
            &x.of
        }
    }
    // scan.rs:34
    {
        fn _a(_: &scan::ScanError) {}
    }
    // scan.rs:63
    {
        let _: fn(u32, u32, bool) -> String = scan::format_list_line;
    }
    // scan.rs:75
    {
        let _: fn(massip::TargetIp, u32, bool) -> String = scan::format_list_line_v46;
    }
    // scan.rs:112
    {
        fn _a(
            range: u64,
            shard: scan::Shard,
            resume_index: u64,
            resume_count: Option<u64>,
            retries: u32,
            max_rate: f64,
        ) -> impl Iterator<Item = u64> + Send {
            scan::list_scan_indices(range, shard, resume_index, resume_count, retries, max_rate)
        }
    }
    // scan.rs:190
    {
        let _: fn(u64, scan::Shard, u32, u32, u64, Option<u64>, u32) -> (u64, u64, u64) =
            scan::transmit_bounds;
    }
    // scan.rs:226
    {
        fn _a(
            range: u64,
            shard: scan::Shard,
            nic_count: u32,
            nic_index: u32,
            resume_index: u64,
            resume_count: Option<u64>,
            retries: u32,
            max_rate: f64,
        ) -> impl Iterator<Item = (u64, u64)> + Send {
            scan::transmit_index_stream(
                range,
                shard,
                nic_count,
                nic_index,
                resume_index,
                resume_count,
                retries,
                max_rate,
            )
        }
    }
    // scan.rs:269
    {
        let _: fn(
            &massip::MassIp,
            u64,
            u32,
            scan::Shard,
            u64,
            Option<u64>,
            u32,
            f64,
            fn(u32, u32),
        ) -> Result<(), scan::ScanError> = scan::list_scan::<fn(u32, u32)>;
    }
    // scan.rs:305
    {
        let _: fn(
            &massip::MassIp,
            u64,
            u32,
            scan::Shard,
            u64,
            Option<u64>,
            u32,
            f64,
            fn(massip::TargetIp, u32),
        ) -> Result<(), scan::ScanError> = scan::list_scan_v46::<fn(massip::TargetIp, u32)>;
    }
    // scan.rs:362
    {
        let _: fn(
            &massip::MassIp,
            u64,
            u32,
            scan::Shard,
            u32,
            u32,
            u64,
            Option<u64>,
            u32,
            f64,
            fn(u64, u64, u64, u32, u32),
        ) -> Result<(), scan::ScanError> = scan::transmit_scan::<fn(u64, u64, u64, u32, u32)>;
    }
    // scan.rs:399
    {
        let _: fn(
            &massip::MassIp,
            u64,
            u32,
            scan::Shard,
            u32,
            u32,
            u64,
            Option<u64>,
            u32,
            f64,
            fn(u64, u64, u64, u32, u32) -> ControlFlow<u8>,
        ) -> Result<ControlFlow<u8>, scan::ScanError> =
            scan::transmit_scan_flow::<u8, fn(u64, u64, u64, u32, u32) -> ControlFlow<u8>>;
    }
    // scan.rs:445
    {
        let _: fn(
            &massip::MassIp,
            u64,
            u32,
            scan::Shard,
            u32,
            u32,
            u64,
            Option<u64>,
            u32,
            f64,
            fn(u64, u64, u64, massip::TargetIp, u32) -> ControlFlow<u8>,
        ) -> Result<ControlFlow<u8>, scan::ScanError> = scan::transmit_scan_flow_v46::<
            u8,
            fn(u64, u64, u64, massip::TargetIp, u32) -> ControlFlow<u8>,
        >;
    }
}

// ===== targets.rs =====
fn check_targets() {
    // targets.rs:11
    {
        fn _a(_: &targets::ParseError) {}
    }
    // targets.rs:24
    {
        const _: u32 = targets::TEMPL_TCP;
    }
    // targets.rs:25
    {
        const _: u32 = targets::TEMPL_TCP_LAST;
    }
    // targets.rs:26
    {
        const _: u32 = targets::TEMPL_UDP;
    }
    // targets.rs:27
    {
        const _: u32 = targets::TEMPL_UDP_LAST;
    }
    // targets.rs:28
    {
        const _: u32 = targets::TEMPL_SCTP;
    }
    // targets.rs:29
    {
        const _: u32 = targets::TEMPL_SCTP_LAST;
    }
    // targets.rs:30
    {
        const _: u32 = targets::TEMPL_ICMP_ECHO;
    }
    // targets.rs:31
    {
        const _: u32 = targets::TEMPL_ICMP_TIMESTAMP;
    }
    // targets.rs:32
    {
        const _: u32 = targets::TEMPL_ARP;
    }
    // targets.rs:33
    {
        const _: u32 = targets::TEMPL_OPROTO_FIRST;
    }
    // targets.rs:34
    {
        const _: u32 = targets::TEMPL_OPROTO_LAST;
    }
    // targets.rs:35
    {
        const _: u32 = targets::TEMPL_VULN_CHECK;
    }
    // targets.rs:86
    {
        let _: fn(&str) -> Result<ranges::Range, targets::ParseError> = targets::range_parse_ipv4;
    }
    // targets.rs:370
    {
        let _: fn(&mut ranges::RangeList, &str) -> Result<(), targets::ParseError> =
            targets::add_target_string;
    }
    // targets.rs:392
    {
        let _: fn(
            &mut ranges::RangeList,
            &mut ranges6::Range6List,
            &str,
        ) -> Result<(), targets::ParseError> = targets::add_target_string_v46;
    }
    // targets.rs:451
    {
        fn _a(_: &targets::PortProto) {}
    }
    // targets.rs:471
    {
        let _: fn(u32) -> (targets::PortProto, u16) = targets::PortProto::from_raw;
    }
    // targets.rs:502
    {
        let _: fn(&mut ranges::RangeList, &str, u32) -> Result<(), targets::ParseError> =
            targets::parse_ports_with;
    }
    // targets.rs:595
    {
        let _: fn(&mut ranges::RangeList, &str) -> Result<(), targets::ParseError> =
            targets::parse_ports;
    }
    // targets.rs:602
    {
        let _: fn(&mut ranges::RangeList, u32, bool, bool) -> () = targets::add_top_ports;
    }
}

// ===== tcp_frame.rs =====
fn check_tcp_frame() {
    // tcp_frame.rs:26
    {
        const _: u16 = tcp_frame::STACK_WINDOW;
    }
    // tcp_frame.rs:53
    {
        let _: for<'a, 'b> fn(
            &'a [u8],
            packet::LinkType,
            &'b probe::ReadyPlan,
        ) -> Option<stack::SegmentIn<'a>> = tcp_frame::tcp_segment;
    }
    // tcp_frame.rs:172
    {
        fn _a(_: &tcp_frame::TcpFrameBuilder) {}
    }
    // tcp_frame.rs:179
    {
        let _: fn(&probe::ReadyPlan) -> tcp_frame::TcpFrameBuilder =
            tcp_frame::TcpFrameBuilder::from_plan;
    }
    // tcp_frame.rs:210
    {
        let _: fn(&tcp_frame::TcpFrameBuilder, &stack::SegmentOut) -> Vec<u8> =
            tcp_frame::TcpFrameBuilder::build;
    }
    // tcp_frame.rs:308
    {
        let _: fn(&receive::Reply, u64) -> Option<stack::SegmentOut> = tcp_frame::stateless_rst;
    }
}

// ===== throttle.rs =====
fn check_throttle() {
    // throttle.rs:14
    {
        const _: u64 = throttle::MAX_SLEEP_CHUNK_MICROS;
    }
    // throttle.rs:19
    {
        let _: throttle::ThrottleCancelled = throttle::ThrottleCancelled;
    }
    // throttle.rs:22
    {
        fn _a(_: &dyn throttle::Clock) {}
    }
    // throttle.rs:35
    {
        fn _a(_: &throttle::SystemClock) {}
    }
    // throttle.rs:40
    {
        let _: fn() -> throttle::SystemClock = throttle::SystemClock::new;
    }
    // throttle.rs:65
    {
        fn _a(_: &throttle::Throttler) {}
    }
    // throttle.rs:77
    {
        fn _a(max_rate: f64, clock: &dyn throttle::Clock) -> throttle::Throttler {
            throttle::Throttler::start(max_rate, clock)
        }
        fn _b(max_rate: f64, clock: &throttle::SystemClock) -> throttle::Throttler {
            throttle::Throttler::start(max_rate, clock)
        }
    }
    // throttle.rs:91
    {
        let _: fn(&throttle::Throttler) -> f64 = throttle::Throttler::max_rate;
    }
    // throttle.rs:95
    {
        let _: fn(&throttle::Throttler) -> f64 = throttle::Throttler::current_rate;
    }
    // throttle.rs:99
    {
        let _: fn(&throttle::Throttler) -> f64 = throttle::Throttler::batch_size;
    }
    // throttle.rs:115
    {
        fn _a(t: &mut throttle::Throttler, packet_count: u64, clock: &dyn throttle::Clock) -> u64 {
            t.next_batch(packet_count, clock)
        }
        fn _b(
            t: &mut throttle::Throttler,
            packet_count: u64,
            clock: &throttle::SystemClock,
        ) -> u64 {
            t.next_batch(packet_count, clock)
        }
    }
    // throttle.rs:125
    {
        fn _a<F: Fn() -> bool>(
            t: &mut throttle::Throttler,
            packet_count: u64,
            clock: &dyn throttle::Clock,
            cancelled: F,
        ) -> Result<u64, throttle::ThrottleCancelled> {
            t.next_batch_interruptible(packet_count, clock, cancelled)
        }
        fn _b(
            t: &mut throttle::Throttler,
            packet_count: u64,
            clock: &throttle::SystemClock,
            cancelled: fn() -> bool,
        ) -> Result<u64, throttle::ThrottleCancelled> {
            t.next_batch_interruptible(packet_count, clock, cancelled)
        }
    }
}

// ===== варианты pub enum =====
fn variants_arp() {
    // arp.rs enum ArpOp
    let _: arp::ArpOp = arp::ArpOp::Request;
    // arp.rs enum ArpOp
    let _: arp::ArpOp = arp::ArpOp::Reply;
    // arp.rs enum ArpError
    let _: fn(usize) -> arp::ArpError = arp::ArpError::Truncated;
    // arp.rs enum ArpError
    let _: arp::ArpError = arp::ArpError::Vlan;
    // arp.rs enum ArpError
    let _: fn(u16) -> arp::ArpError = arp::ArpError::NotArp;
    // arp.rs enum ArpError
    let _: fn(u16) -> arp::ArpError = arp::ArpError::BadHardwareType;
    // arp.rs enum ArpError
    let _: fn(u16) -> arp::ArpError = arp::ArpError::BadProtocolType;
    // arp.rs enum ArpError
    let _: fn(u8, u8) -> arp::ArpError =
        |hw: u8, proto: u8| arp::ArpError::BadLengths { hw, proto };
    // arp.rs enum ArpError
    let _: fn(u16) -> arp::ArpError = arp::ArpError::BadOpcode;
}
fn variants_blackrock() {
    // blackrock.rs enum BlackRockError
    let _: blackrock::BlackRockError = blackrock::BlackRockError::EmptyRange;
    // blackrock.rs enum BlackRockError
    let _: blackrock::BlackRockError = blackrock::BlackRockError::TooManyRounds;
}
fn variants_massip() {
    // massip.rs enum TargetIp
    let _: fn(u32) -> massip::TargetIp = massip::TargetIp::V4;
    // massip.rs enum TargetIp
    let _: fn(u128) -> massip::TargetIp = massip::TargetIp::V6;
}
fn variants_ndp() {
    // ndp.rs enum NdpError
    let _: fn(usize) -> ndp::NdpError = ndp::NdpError::Truncated;
    // ndp.rs enum NdpError
    let _: fn(u16) -> ndp::NdpError = ndp::NdpError::NotIpv6;
    // ndp.rs enum NdpError
    let _: fn(u8) -> ndp::NdpError = ndp::NdpError::NotIcmpv6;
    // ndp.rs enum NdpError
    let _: fn(usize, usize) -> ndp::NdpError =
        |payload: usize, available: usize| ndp::NdpError::PayloadBeyondFrame { payload, available };
    // ndp.rs enum NdpError
    let _: fn(u8) -> ndp::NdpError = ndp::NdpError::WrongType;
    // ndp.rs enum NdpError
    let _: fn(u8) -> ndp::NdpError = ndp::NdpError::HopLimit;
    // ndp.rs enum NdpError
    let _: fn(u8) -> ndp::NdpError = ndp::NdpError::Code;
    // ndp.rs enum NdpError
    let _: fn(usize) -> ndp::NdpError = ndp::NdpError::Length;
    // ndp.rs enum NdpError
    let _: ndp::NdpError = ndp::NdpError::Checksum;
    // ndp.rs enum NdpError
    let _: ndp::NdpError = ndp::NdpError::TargetMulticast;
    // ndp.rs enum NdpError
    let _: ndp::NdpError = ndp::NdpError::BadOption;
    // ndp.rs enum NdpError
    let _: ndp::NdpError = ndp::NdpError::NoTargetLla;
    // ndp.rs enum NdpError
    let _: ndp::NdpError = ndp::NdpError::UnspecifiedSource;
    // ndp.rs enum NdpError
    let _: ndp::NdpError = ndp::NdpError::SolicitedToMulticast;
}
fn variants_packet() {
    // packet.rs enum LinkType
    let _: packet::LinkType = packet::LinkType::Ethernet;
    // packet.rs enum LinkType
    let _: packet::LinkType = packet::LinkType::Null;
    // packet.rs enum LinkType
    let _: packet::LinkType = packet::LinkType::Raw;
}
fn variants_payloads() {
    // payloads.rs enum CookieMutator
    let _: payloads::CookieMutator = payloads::CookieMutator::Dns;
    // payloads.rs enum CookieMutator
    let _: payloads::CookieMutator = payloads::CookieMutator::Ntp;
    // payloads.rs enum CookieMutator
    let _: payloads::CookieMutator = payloads::CookieMutator::Snmp;
    // payloads.rs enum CookieMutator
    let _: payloads::CookieMutator = payloads::CookieMutator::Isakmp;
    // payloads.rs enum CookieMutator
    let _: payloads::CookieMutator = payloads::CookieMutator::Coap;
    // payloads.rs enum CookieMutator
    let _: payloads::CookieMutator = payloads::CookieMutator::Memcached;
    // payloads.rs enum PayloadError
    let _: fn(usize, &'static str) -> payloads::PayloadError =
        |line: usize, msg: &'static str| payloads::PayloadError::Syntax { line, msg };
    // payloads.rs enum PayloadError
    let _: fn(&'static str) -> payloads::PayloadError = payloads::PayloadError::Pcap;
    // payloads.rs enum PayloadError
    let _: fn(u32, usize) -> payloads::PayloadError =
        |port: u32, len: usize| payloads::PayloadError::TooLong { port, len };
}
fn variants_probe() {
    // probe.rs enum PlanError
    let _: fn(config::Operation) -> probe::PlanError = probe::PlanError::NotScanOperation;
    // probe.rs enum PlanError
    let _: fn(u64) -> probe::PlanError = probe::PlanError::ResumeIndexNotAllowed;
    // probe.rs enum PlanError
    let _: fn(u64) -> probe::PlanError = probe::PlanError::ResumeCountNotAllowed;
    // probe.rs enum PlanError
    let _: fn(u32, u32) -> probe::PlanError =
        |one: u32, of: u32| probe::PlanError::UnsupportedShard { one, of };
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::UnsupportedRetries;
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::UnsupportedRounds;
    // probe.rs enum PlanError
    let _: fn(u16, u16) -> probe::PlanError =
        |first: u16, last: u16| probe::PlanError::InvalidSourcePorts { first, last };
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::UnsupportedPacketModifiers;
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::PortNotTcp;
    // probe.rs enum PlanError
    let _: fn(u32, u32) -> probe::PlanError =
        |port_them: u32, port_me: u32| probe::PlanError::PortDoesNotFit { port_them, port_me };
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::OprotoNotSupported;
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::IcmpTypeNotSupported;
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::ArpMixedWithPorts;
    // probe.rs enum PlanError
    let _: fn(Box<probe::PlanError>) -> probe::PlanError = probe::PlanError::ProbeBuild;
    // probe.rs enum PlanError
    let _: fn(u64, u64) -> probe::PlanError =
        |next_index: u64, limit: u64| probe::PlanError::NextIndexBeyondRange { next_index, limit };
    // probe.rs enum PlanError
    let _: fn(u32, u32) -> probe::PlanError =
        |one: u32, of: u32| probe::PlanError::InvalidShard { one, of };
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::TooManyRetries;
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::ZeroRounds;
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::Ipv6TargetsNotSupported;
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::Ipv6PortNotTcp;
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::NoSourceIpv6;
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::NoNextHopMacIpv6;
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::Ipv6NextHopIsSourceMac;
    // probe.rs enum PlanError
    let _: fn(usize) -> probe::PlanError = probe::PlanError::BadNicCount;
    // probe.rs enum PlanError
    let _: fn(u32, usize) -> probe::PlanError =
        |index: u32, count: usize| probe::PlanError::NicIndexOutOfRange { index, count };
    // probe.rs enum PlanError
    let _: fn(u32, u32) -> probe::PlanError =
        |first: u32, last: u32| probe::PlanError::InvalidSourceIpv4 { first, last };
    // probe.rs enum PlanError
    let _: probe::PlanError = probe::PlanError::DestinationsRequireEthernet;
    // probe.rs enum PlanError
    let _: fn(u64, usize) -> probe::PlanError = |expected: u64, actual: usize| {
        probe::PlanError::DestinationCountMismatch { expected, actual }
    };
    // probe.rs enum PlanError
    let _: fn(u32) -> probe::PlanError = probe::PlanError::UnexpectedDestination;
    // probe.rs enum PlanError
    let _: fn(u32, [u8; 6]) -> probe::PlanError =
        |ip: u32, mac: [u8; 6]| probe::PlanError::InvalidDestinationMac { ip, mac };
    // probe.rs enum PlanError
    let _: fn(scan::ScanError) -> probe::PlanError = probe::PlanError::Scan;
}
fn variants_receive() {
    // receive.rs enum ChecksumPolicy
    let _: receive::ChecksumPolicy = receive::ChecksumPolicy::Verify;
    // receive.rs enum ChecksumPolicy
    let _: receive::ChecksumPolicy = receive::ChecksumPolicy::TrustHardware;
    // receive.rs enum Unsupported
    let _: receive::Unsupported = receive::Unsupported::Vlan;
    // receive.rs enum ParseError
    let _: fn(usize) -> receive::ParseError = receive::ParseError::FrameTooLong;
    // receive.rs enum ParseError
    let _: fn(&'static str) -> receive::ParseError = receive::ParseError::Truncated;
    // receive.rs enum ParseError
    let _: fn(u8) -> receive::ParseError = receive::ParseError::BadIpVersion;
    // receive.rs enum ParseError
    let _: fn(u8) -> receive::ParseError = receive::ParseError::BadIpv4HeaderLength;
    // receive.rs enum ParseError
    let _: fn(u16, usize) -> receive::ParseError =
        |total: u16, header: usize| receive::ParseError::TotalLengthBelowHeader { total, header };
    // receive.rs enum ParseError
    let _: fn(u16, usize) -> receive::ParseError = |total: u16, available: usize| {
        receive::ParseError::TotalLengthBeyondFrame { total, available }
    };
    // receive.rs enum ParseError
    let _: receive::ParseError = receive::ParseError::Fragment;
    // receive.rs enum ParseError
    let _: fn(u16, usize) -> receive::ParseError = |payload: u16, available: usize| {
        receive::ParseError::Ipv6PayloadBeyondFrame { payload, available }
    };
    // receive.rs enum ParseError
    let _: fn(u8) -> receive::ParseError = receive::ParseError::BadTcpDataOffset;
    // receive.rs enum ParseError
    let _: fn(receive::Unsupported) -> receive::ParseError = receive::ParseError::Unsupported;
    // receive.rs enum ParseError
    let _: fn(u32) -> receive::ParseError = receive::ParseError::UnknownNullFamily;
    // receive.rs enum ParseError
    let _: fn(u32) -> receive::ParseError = receive::ParseError::UnsupportedLinkType;
    // receive.rs enum ParseError
    let _: receive::ParseError = receive::ParseError::BadIpChecksum;
    // receive.rs enum ParseError
    let _: receive::ParseError = receive::ParseError::BadTcpChecksum;
    // receive.rs enum ParseError
    let _: receive::ParseError = receive::ParseError::BadIcmpChecksum;
    // receive.rs enum ParseError
    let _: fn(u16) -> receive::ParseError = receive::ParseError::BadUdpLength;
    // receive.rs enum ParseError
    let _: receive::ParseError = receive::ParseError::BadUdpChecksum;
    // receive.rs enum ParseError
    let _: receive::ParseError = receive::ParseError::BadSctpChecksum;
    // receive.rs enum PortStatus
    let _: receive::PortStatus = receive::PortStatus::Open;
    // receive.rs enum PortStatus
    let _: receive::PortStatus = receive::PortStatus::Closed;
    // receive.rs enum PortStatus
    let _: receive::PortStatus = receive::PortStatus::Arp;
}
fn variants_scan() {
    // scan.rs enum ScanError
    let _: scan::ScanError = scan::ScanError::EmptyRange;
    // scan.rs enum ScanError
    let _: fn(massip::RangeOverflow) -> scan::ScanError = scan::ScanError::RangeOverflow;
    // scan.rs enum ScanError
    let _: scan::ScanError = scan::ScanError::ZeroShard;
    // scan.rs enum ScanError
    let _: scan::ScanError = scan::ScanError::Ipv6Targets;
    // scan.rs enum ScanError
    let _: fn(blackrock::BlackRockError) -> scan::ScanError = scan::ScanError::BlackRock;
    // scan.rs enum ScanError
    let _: fn(u64) -> scan::ScanError = |index: u64| scan::ScanError::NonTerminating { index };
}
fn variants_targets() {
    // targets.rs enum ParseError
    let _: targets::ParseError = targets::ParseError::BadIpv4;
    // targets.rs enum ParseError
    let _: targets::ParseError = targets::ParseError::BadPort;
    // targets.rs enum ParseError
    let _: targets::ParseError = targets::ParseError::Ipv6NotSupported;
    // targets.rs enum ParseError
    let _: targets::ParseError = targets::ParseError::ReversedRange;
    // targets.rs enum ParseError
    let _: targets::ParseError = targets::ParseError::BadIpv6;
    // targets.rs enum PortProto
    let _: targets::PortProto = targets::PortProto::Tcp;
    // targets.rs enum PortProto
    let _: targets::PortProto = targets::PortProto::Udp;
    // targets.rs enum PortProto
    let _: targets::PortProto = targets::PortProto::Sctp;
    // targets.rs enum PortProto
    let _: targets::PortProto = targets::PortProto::IcmpEcho;
    // targets.rs enum PortProto
    let _: fn(u8) -> targets::PortProto = targets::PortProto::IcmpOther;
    // targets.rs enum PortProto
    let _: targets::PortProto = targets::PortProto::Arp;
    // targets.rs enum PortProto
    let _: fn(u8) -> targets::PortProto = targets::PortProto::Oproto;
}

// ===== производные и авто-трейты =====
fn traits() {
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<arp::ArpOp>();
    } // arp.rs ArpOp derives
    {
        fn a<T: Send + Sync>() {}
        a::<arp::ArpOp>();
    } // arp.rs ArpOp auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<arp::ArpError>();
    } // arp.rs ArpError derives
    {
        fn a<T: Send + Sync>() {}
        a::<arp::ArpError>();
    } // arp.rs ArpError auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<arp::ArpPacket>();
    } // arp.rs ArpPacket derives
    {
        fn a<T: Send + Sync>() {}
        a::<arp::ArpPacket>();
    } // arp.rs ArpPacket auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<arp::IncomingRequest>();
    } // arp.rs IncomingRequest derives
    {
        fn a<T: Send + Sync>() {}
        a::<arp::IncomingRequest>();
    } // arp.rs IncomingRequest auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<arp::PendingResolve>();
    } // arp.rs PendingResolve derives
    {
        fn a<T: Send + Sync>() {}
        a::<arp::PendingResolve>();
    } // arp.rs PendingResolve auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<blackrock::BlackRockError>();
    } // blackrock.rs BlackRockError derives
    {
        fn a<T: Send + Sync>() {}
        a::<blackrock::BlackRockError>();
    } // blackrock.rs BlackRockError auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<blackrock::BlackRock>();
    } // blackrock.rs BlackRock derives
    {
        fn a<T: Send + Sync>() {}
        a::<blackrock::BlackRock>();
    } // blackrock.rs BlackRock auto traits
    {
        fn a<T: Send + Sync>() {}
        a::<massip::RangeOverflow>();
    } // massip.rs RangeOverflow auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::hash::Hash>() {}
        a::<massip::TargetIp>();
    } // massip.rs TargetIp derives
    {
        fn a<T: Send + Sync>() {}
        a::<massip::TargetIp>();
    } // massip.rs TargetIp auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Default>() {}
        a::<massip::MassIp>();
    } // massip.rs MassIp derives
    {
        fn a<T: Send + Sync>() {}
        a::<massip::MassIp>();
    } // massip.rs MassIp auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<ndp::NdpError>();
    } // ndp.rs NdpError derives
    {
        fn a<T: Send + Sync>() {}
        a::<ndp::NdpError>();
    } // ndp.rs NdpError auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<ndp::NeighborAdvertisement>();
    } // ndp.rs NeighborAdvertisement derives
    {
        fn a<T: Send + Sync>() {}
        a::<ndp::NeighborAdvertisement>();
    } // ndp.rs NeighborAdvertisement auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<ndp::NeighborSolicitation>();
    } // ndp.rs NeighborSolicitation derives
    {
        fn a<T: Send + Sync>() {}
        a::<ndp::NeighborSolicitation>();
    } // ndp.rs NeighborSolicitation auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<ndp::PendingNdp>();
    } // ndp.rs PendingNdp derives
    {
        fn a<T: Send + Sync>() {}
        a::<ndp::PendingNdp>();
    } // ndp.rs PendingNdp auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<packet::LinkType>();
    } // packet.rs LinkType derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::LinkType>();
    } // packet.rs LinkType auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<packet::TcpHeaderOptions>();
    } // packet.rs TcpHeaderOptions derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::TcpHeaderOptions>();
    } // packet.rs TcpHeaderOptions auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<packet::PacketModifiers>();
    } // packet.rs PacketModifiers derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::PacketModifiers>();
    } // packet.rs PacketModifiers auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<packet::TcpSynTemplate>();
    } // packet.rs TcpSynTemplate derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::TcpSynTemplate>();
    } // packet.rs TcpSynTemplate auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<packet::Tcp6SynTemplate>();
    } // packet.rs Tcp6SynTemplate derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::Tcp6SynTemplate>();
    } // packet.rs Tcp6SynTemplate auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<packet::IcmpEchoTemplate>();
    } // packet.rs IcmpEchoTemplate derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::IcmpEchoTemplate>();
    } // packet.rs IcmpEchoTemplate auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<packet::UdpTemplate>();
    } // packet.rs UdpTemplate derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::UdpTemplate>();
    } // packet.rs UdpTemplate auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<packet::SctpTemplate>();
    } // packet.rs SctpTemplate derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::SctpTemplate>();
    } // packet.rs SctpTemplate auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<packet::ArpTemplate>();
    } // packet.rs ArpTemplate derives
    {
        fn a<T: Send + Sync>() {}
        a::<packet::ArpTemplate>();
    } // packet.rs ArpTemplate auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<payloads::CookieMutator>();
    } // payloads.rs CookieMutator derives
    {
        fn a<T: Send + Sync>() {}
        a::<payloads::CookieMutator>();
    } // payloads.rs CookieMutator auto traits
    {
        fn a<T: Clone + std::fmt::Debug + PartialEq + Eq>() {}
        a::<payloads::PayloadEntry>();
    } // payloads.rs PayloadEntry derives
    {
        fn a<T: Send + Sync>() {}
        a::<payloads::PayloadEntry>();
    } // payloads.rs PayloadEntry auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<payloads::PayloadError>();
    } // payloads.rs PayloadError derives
    {
        fn a<T: Send + Sync>() {}
        a::<payloads::PayloadError>();
    } // payloads.rs PayloadError auto traits
    {
        fn a<T: Clone + std::fmt::Debug>() {}
        a::<payloads::PayloadTable>();
    } // payloads.rs PayloadTable derives
    {
        fn a<T: Send + Sync>() {}
        a::<payloads::PayloadTable>();
    } // payloads.rs PayloadTable auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<probe::PlanError>();
    } // probe.rs PlanError derives
    {
        fn a<T: Send + Sync>() {}
        a::<probe::PlanError>();
    } // probe.rs PlanError auto traits
    {
        fn a<T: std::fmt::Debug + Clone + PartialEq + Eq>() {}
        a::<probe::AdapterBinding>();
    } // probe.rs AdapterBinding derives
    {
        fn a<T: Send + Sync>() {}
        a::<probe::AdapterBinding>();
    } // probe.rs AdapterBinding auto traits
    {
        fn a<T: std::fmt::Debug + Clone + PartialEq + Eq>() {}
        a::<probe::NicBinding>();
    } // probe.rs NicBinding derives
    {
        fn a<T: Send + Sync>() {}
        a::<probe::NicBinding>();
    } // probe.rs NicBinding auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Default + PartialEq + Eq>() {}
        a::<probe::Probe>();
    } // probe.rs Probe derives
    {
        fn a<T: Send + Sync>() {}
        a::<probe::Probe>();
    } // probe.rs Probe auto traits
    {
        fn a<T: std::fmt::Debug + Clone>() {}
        a::<probe::ReadyPlan>();
    } // probe.rs ReadyPlan derives
    {
        fn a<T: Send + Sync>() {}
        a::<probe::ReadyPlan>();
    } // probe.rs ReadyPlan auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<ranges::Range>();
    } // ranges.rs Range derives
    {
        fn a<T: Send + Sync>() {}
        a::<ranges::Range>();
    } // ranges.rs Range auto traits
    {
        fn a<T: std::fmt::Debug + Clone>() {}
        a::<ranges::RangeList>();
    } // ranges.rs RangeList derives
    {
        fn a<T: Send + Sync>() {}
        a::<ranges::RangeList>();
    } // ranges.rs RangeList auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::hash::Hash>() {}
        a::<ranges6::Ipv6AddrBytes>();
    } // ranges6.rs Ipv6AddrBytes derives
    {
        fn a<T: Send + Sync>() {}
        a::<ranges6::Ipv6AddrBytes>();
    } // ranges6.rs Ipv6AddrBytes auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<ranges6::Ipv6Range>();
    } // ranges6.rs Ipv6Range derives
    {
        fn a<T: Send + Sync>() {}
        a::<ranges6::Ipv6Range>();
    } // ranges6.rs Ipv6Range auto traits
    {
        fn a<T: std::fmt::Debug + Clone>() {}
        a::<ranges6::Range6List>();
    } // ranges6.rs Range6List derives
    {
        fn a<T: Send + Sync>() {}
        a::<ranges6::Range6List>();
    } // ranges6.rs Range6List auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq + Default>() {}
        a::<receive::ChecksumPolicy>();
    } // receive.rs ChecksumPolicy derives
    {
        fn a<T: Send + Sync>() {}
        a::<receive::ChecksumPolicy>();
    } // receive.rs ChecksumPolicy auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<receive::Unsupported>();
    } // receive.rs Unsupported derives
    {
        fn a<T: Send + Sync>() {}
        a::<receive::Unsupported>();
    } // receive.rs Unsupported auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<receive::ParseError>();
    } // receive.rs ParseError derives
    {
        fn a<T: Send + Sync>() {}
        a::<receive::ParseError>();
    } // receive.rs ParseError auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<receive::PortStatus>();
    } // receive.rs PortStatus derives
    {
        fn a<T: Send + Sync>() {}
        a::<receive::PortStatus>();
    } // receive.rs PortStatus auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<receive::ReplyIpv6>();
    } // receive.rs ReplyIpv6 derives
    {
        fn a<T: Send + Sync>() {}
        a::<receive::ReplyIpv6>();
    } // receive.rs ReplyIpv6 auto traits
    {
        fn a<T: Clone + Copy + std::fmt::Debug + PartialEq + Eq>() {}
        a::<receive::Reply>();
    } // receive.rs Reply derives
    {
        fn a<T: Send + Sync>() {}
        a::<receive::Reply>();
    } // receive.rs Reply auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<scan::Shard>();
    } // scan.rs Shard derives
    {
        fn a<T: Send + Sync>() {}
        a::<scan::Shard>();
    } // scan.rs Shard auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<scan::ScanError>();
    } // scan.rs ScanError derives
    {
        fn a<T: Send + Sync>() {}
        a::<scan::ScanError>();
    } // scan.rs ScanError auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<targets::ParseError>();
    } // targets.rs ParseError derives
    {
        fn a<T: Send + Sync>() {}
        a::<targets::ParseError>();
    } // targets.rs ParseError auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq>() {}
        a::<targets::PortProto>();
    } // targets.rs PortProto derives
    {
        fn a<T: Send + Sync>() {}
        a::<targets::PortProto>();
    } // targets.rs PortProto auto traits
    {
        fn a<T: Clone + std::fmt::Debug + PartialEq + Eq>() {}
        a::<tcp_frame::TcpFrameBuilder>();
    } // tcp_frame.rs TcpFrameBuilder derives
    {
        fn a<T: Send + Sync>() {}
        a::<tcp_frame::TcpFrameBuilder>();
    } // tcp_frame.rs TcpFrameBuilder auto traits
    {
        fn a<
            T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::error::Error + std::fmt::Display,
        >() {
        }
        a::<throttle::ThrottleCancelled>();
    } // throttle.rs ThrottleCancelled derives
    {
        fn a<T: Send + Sync>() {}
        a::<throttle::ThrottleCancelled>();
    } // throttle.rs ThrottleCancelled auto traits
    {
        fn a<T: std::fmt::Debug + Clone + Copy>() {}
        a::<throttle::SystemClock>();
    } // throttle.rs SystemClock derives
    {
        fn a<T: Send + Sync>() {}
        a::<throttle::SystemClock>();
    } // throttle.rs SystemClock auto traits
    {
        fn a<T: std::fmt::Debug + Clone>() {}
        a::<throttle::Throttler>();
    } // throttle.rs Throttler derives
    {
        fn a<T: Send + Sync>() {}
        a::<throttle::Throttler>();
    } // throttle.rs Throttler auto traits
    // Ручные реализации трейтов.
    {
        fn a<T: Default>() {}
        a::<massip::TargetIp>();
        a::<packet::TcpHeaderOptions>();
        a::<packet::PacketModifiers>();
        a::<payloads::PayloadTable>();
        a::<ranges::RangeList>();
        a::<ranges6::Range6List>();
        a::<scan::Shard>();
        a::<throttle::SystemClock>();
    }
    {
        fn a<T: From<probe::AdapterBinding>>() {}
        a::<probe::NicBinding>();
    }
    {
        fn a<T: From<u128>>() {}
        a::<ranges6::Ipv6AddrBytes>();
    }
    {
        fn a<T: std::fmt::Debug>() {}
        a::<probe::ProbeCursor>();
    }
    {
        fn a<T: Send>() {}
        a::<probe::ProbeCursor>();
    }
    {
        fn a<T: From<scan::ScanError>>() {}
        a::<probe::PlanError>();
    }
    {
        fn a<T: From<massip::RangeOverflow> + From<blackrock::BlackRockError>>() {}
        a::<scan::ScanError>();
    }
    {
        fn a<T: throttle::Clock>() {}
        a::<throttle::SystemClock>();
    }
    // Методы трейта `Clock` (в инвентарь не входят: у методов трейта нет `pub`).
    fn _clock(c: &dyn throttle::Clock) -> u64 {
        c.sleep_micros(0);
        c.now_micros()
    }
}

/// Сами проверки собираются, а не выполняются: тест нужен, чтобы файл был целью `cargo test`.
#[test]
fn api_freeze_compiles() {}
