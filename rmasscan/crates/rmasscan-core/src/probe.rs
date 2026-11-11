//! Генерация probe: SYN-cookie, порт источника и кадр (AGPL-3.0). Порт
//! формулы `transmit_thread` (`src/main.c:371-402`) из masscan © Robert David
//! Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0). Формула
//! перенесена из CLI без изменения байтов; перестановка и индексы берутся из
//! [`crate::scan`] и [`crate::blackrock`], здесь они не переписаны.
//!
//! Два входа:
//! - [`ReadyPlan`] + [`ProbeCursor`]: runtime. Курсор отдаёт один и тот же
//!   probe, пока вызывающий не подтвердит отправку ([`ProbeCursor::advance_sent`]).
//!   [`ReadyPlan::new`] принимает только то, что runtime v1 умеет (shard 1/1,
//!   NIC 1, retries 0, rounds 14) и только новый запуск: продолжение идёт через
//!   checkpoint, не через `resume_index`/`resume_count`. [`ReadyPlan::new_cli`]
//!   принимает любой валидный shard, retries до 999, `resume_*` и до 8 адаптеров.
//! - [`for_each_probe`]: потоковый оракул для CLI (`--offline --packet-trace`),
//!   сохраняет все алгоритмы этапа 1 (retries, shard), с остановкой через
//!   [`ControlFlow`].

use std::collections::VecDeque;
use std::iter::Peekable;
use std::ops::ControlFlow;
use std::sync::Arc;

use crate::blackrock::BlackRock;
use crate::config::{EffectiveConfig, Operation};
use crate::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
pub use crate::massip::TargetIp;
use crate::packet::{
    ArpTemplate, IcmpEchoTemplate, LinkType, PacketModifiers, SctpTemplate, Tcp6SynTemplate,
    TcpSynTemplate, UdpTemplate,
};
use crate::payloads::PayloadTable;
use crate::ranges::RangeList;
use crate::scan::{ScanError, Shard, transmit_bounds, transmit_index_stream, transmit_scan_flow};
use crate::targets::{
    TEMPL_ARP, TEMPL_ICMP_ECHO, TEMPL_OPROTO_FIRST, TEMPL_OPROTO_LAST, TEMPL_SCTP, TEMPL_SCTP_LAST,
    TEMPL_UDP, TEMPL_UDP_LAST,
};

/// Раунды BlackRock, которые принимает runtime v1 (masscan по умолчанию).
pub const RUNTIME_BLACKROCK_ROUNDS: u32 = 14;

/// Ошибки плана и генерации probe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("plan needs a scan configuration, got {0:?}")]
    NotScanOperation(Operation),
    #[error("legacy resume index {0} is not accepted for a new run (resume via checkpoint)")]
    ResumeIndexNotAllowed(u64),
    #[error("legacy resume count {0} is not accepted for a new run (resume via checkpoint)")]
    ResumeCountNotAllowed(u64),
    #[error("unsupported shard {one}/{of}: runtime v1 runs only shard 1/1")]
    UnsupportedShard { one: u32, of: u32 },
    #[error("unsupported retries {0}: runtime v1 runs only retries 0")]
    UnsupportedRetries(u32),
    #[error("unsupported blackrock rounds {0}: runtime v1 runs only {RUNTIME_BLACKROCK_ROUNDS}")]
    UnsupportedRounds(u32),
    #[error(
        "invalid source ports {first}-{last}: need 1 <= first <= last and a power-of-two width"
    )]
    InvalidSourcePorts { first: u16, last: u16 },
    #[error(
        "runtime v1 sends only default probe parameters (ttl 255, no badsum, default TCP options); use the CLI plan"
    )]
    UnsupportedPacketModifiers,
    #[error("target port {0} does not fit TCP (v1 is TCP only)")]
    PortNotTcp(u32),
    #[error("port {port_them}/{port_me} does not fit TCP (v1 is TCP only)")]
    PortDoesNotFit { port_them: u32, port_me: u32 },
    #[error("raw IP protocol ports (O:{}) are not supported for scanning; rmasscan sends no raw-protocol probes", .0 - TEMPL_OPROTO_FIRST)]
    OprotoNotSupported(u32),
    #[error("ICMP ports other than I:0 (echo) and the ARP index are not supported for scanning (I:{})", .0 - TEMPL_ICMP_ECHO)]
    IcmpTypeNotSupported(u32),
    #[error("ARP scan cannot be mixed with other ports")]
    ArpMixedWithPorts,
    /// Построитель зонда отказал посреди прохода: это отказ скана, а не его конец.
    #[error("probe could not be built: {0}")]
    ProbeBuild(Box<PlanError>),
    #[error("next index {next_index} is beyond the transmit limit {limit}")]
    NextIndexBeyondRange { next_index: u64, limit: u64 },
    #[error("invalid shard {one}/{of}: need 1 <= one <= of")]
    InvalidShard { one: u32, of: u32 },
    #[error("retries must be at most 999, got {0}")]
    TooManyRetries(u32),
    #[error("blackrock rounds must be at least 1, got {0}")]
    ZeroRounds(u32),
    /// Цели IPv6: скан пока не умеет ни живого, ни `--packet-trace` пути (R7). C
    /// шлёт их; здесь отказ до первого кадра, а не молчаливый пропуск.
    #[error(
        "IPv6 targets cannot be scanned yet: IPv6 is accepted only for -sL, --echo and --offline \
         (without --packet-trace)"
    )]
    Ipv6TargetsNotSupported,
    /// IPv6-зонд без адреса источника IPv6 у адаптера (`NicBinding::source_ipv6`): C берёт `src.ipv6`
    /// (main.c:345), нулевой адрес ушёл бы в провод молча.
    #[error("the adapter has no IPv6 source address (source_ipv6), so no IPv6 probe can be built")]
    NoSourceIpv6,
    #[error("need 1..=8 adapters, got {0}")]
    BadNicCount(usize),
    #[error("adapter index {index} is out of range for {count} adapters")]
    NicIndexOutOfRange { index: u32, count: usize },
    #[error(
        "invalid source addresses {first:#010x}-{last:#010x}: need first <= last and a power-of-two width"
    )]
    InvalidSourceIpv4 { first: u32, last: u32 },
    #[error(transparent)]
    Scan(#[from] ScanError),
}

/// Разрешённые, неизменяемые параметры адаптера для генерации кадров.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterBinding {
    pub interface_id: String,
    pub link_type: LinkType,
    pub source_ipv4: u32,
    pub source_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
    /// `(first, last)` включительно; ширина должна быть степенью двойки.
    pub source_ports: (u16, u16),
}

/// Адаптер плана CLI: [`AdapterBinding`] плюс диапазон адресов источника и
/// режим C для не-степени-двойки ширины портов. Студия остаётся на
/// [`AdapterBinding`]: его 6 полей заморожены.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicBinding {
    pub binding: AdapterBinding,
    /// Последний адрес источника (включительно); `ipv4_mask = last - first`
    /// (main.c:183). Равен `binding.source_ipv4` для одного адреса.
    pub source_ipv4_last: u32,
    /// C сам пишет в `paused.conf` порты `p-(p+16)` (17 портов, не степень
    /// двойки; main.c:1318, main-conf.c:3668). С флагом принимается ровно
    /// `last - first == 16` (спека Р6), маска остаётся `last - first`
    /// (main.c:186). Флаг у каждого адаптера свой.
    pub legacy_c_17_port_mask: bool,
    /// Адрес источника IPv6 (`adapter_get_source_addresses`, main.c:188: `src->ipv6 = ifsrc->ipv6.first`, "TODO:
    /// currently supports only a single address", :190-192). Один адрес, без диапазона и без ротации; порт
    /// источника IPv6 всегда `source_ports.0` (main.c:346). `None` у плана IPv4 и у Студии. Приёмник считает кадр
    /// IPv6 своим, только если адрес назначения равен этому (`is_my_ip`, stack-src.c:13-14).
    pub source_ipv6: Option<u128>,
}

impl From<AdapterBinding> for NicBinding {
    fn from(binding: AdapterBinding) -> NicBinding {
        NicBinding {
            source_ipv4_last: binding.source_ipv4,
            legacy_c_17_port_mask: false,
            source_ipv6: None,
            binding,
        }
    }
}

/// Одна отправка SYN (main.c:371-402).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    /// Внешний индекс цикла `i` (main.c:431): при `retries > 0` или shard это
    /// не порядковый номер кадра, а один `i` на всю пачку повторов.
    pub index: u64,
    pub ip_me: u32,
    pub port_me: u16,
    pub ip_them: u32,
    /// Цель как `TargetIp` (R2): рядом с IPv4-полями `ip_them` и `port_them`, которые остаются
    /// прежними и дают те же байты кадра. Сейчас всегда `V4(ip_them)`: IPv6-цели план отклоняет
    /// ([`PlanError::Ipv6TargetsNotSupported`]), а `V6` понадобится живому пути IPv6.
    pub target: TargetIp,
    pub port_them: u16,
    /// Порт цели с протокольным смещением, как `port_them` в `transmit_thread` (main.c:389): порт TCP как есть,
    /// `65536 + порт` для UDP, `196608` для ICMP Echo. Этот индекс (а не 16-битный `port_them`) входит в cookie.
    pub port_index: u32,
    pub seqno: u32,
    pub frame: Vec<u8>,
}

fn check_source_ports(first: u16, last: u16, legacy_c_17: bool) -> Result<(), PlanError> {
    let width = u32::from(last)
        .wrapping_sub(u32::from(first))
        .wrapping_add(1);
    // Поблажка C (main.c:1318) только для 17 портов, `last - first == 16`.
    let lenient = legacy_c_17 && width == 17;
    if first == 0 || first > last || !(lenient || width.is_power_of_two()) {
        return Err(PlanError::InvalidSourcePorts { first, last });
    }
    Ok(())
}

/// Формула источника и кадра (main.c:373-402).
#[derive(Debug, Clone)]
struct Builder {
    tmpl: TcpSynTemplate,
    /// Шаблон TCP SYN поверх IPv6 (78 байт, templ-pkt.c:1110-1202), `router_mac_ipv6` это `next_hop_mac` адаптера.
    tmpl6: Tcp6SynTemplate,
    /// `src.ipv6` (main.c:188); `None`: IPv6-зонд отказывает ([`PlanError::NoSourceIpv6`]).
    source_ipv6: Option<u128>,
    /// Шаблон ICMP Echo (`I:0`, templ-pkt.c:105): тот же путь адаптера, что у TCP.
    icmp: IcmpEchoTemplate,
    /// Шаблон UDP (`U:`, templ-pkt.c:56): тот же путь адаптера и та же таблица нагрузок на все адаптеры.
    udp: UdpTemplate,
    /// Шаблон SCTP INIT (`S:`, templ-pkt.c:76): тот же путь адаптера.
    sctp: SctpTemplate,
    /// Шаблон ARP who-has (`--arp`, `I:2`, templ-pkt.c:162): тот же путь адаптера, всегда широковещательный.
    arp: ArpTemplate,
    payloads: Arc<PayloadTable>,
    ip_me0: u32,
    first: u16,
    port_mask: u32,
    /// main.c:183 `ipv4_mask = ipv4.last - ipv4.first`.
    ipv4_mask: u32,
    entropy: u64,
}

impl Builder {
    fn from_nic(
        nic: &NicBinding,
        seed: u64,
        mods: &PacketModifiers,
        payloads: &Arc<PayloadTable>,
    ) -> Result<Builder, PlanError> {
        let binding = &nic.binding;
        let (first, last) = binding.source_ports;
        check_source_ports(first, last, nic.legacy_c_17_port_mask)?;
        // main-conf.c:2483: ширина диапазона адресов источника степень двойки; только тогда
        // `ipv4_mask = last - first` (main.c:183, :384) работает как маска.
        let ip_width = u64::from(nic.source_ipv4_last)
            .wrapping_sub(u64::from(binding.source_ipv4))
            .wrapping_add(1);
        if nic.source_ipv4_last < binding.source_ipv4 || !ip_width.is_power_of_two() {
            return Err(PlanError::InvalidSourceIpv4 {
                first: binding.source_ipv4,
                last: nic.source_ipv4_last,
            });
        }
        Ok(Builder {
            tmpl: TcpSynTemplate::new_with_options(
                binding.source_mac,
                binding.next_hop_mac,
                binding.link_type,
                mods,
            ),
            tmpl6: Tcp6SynTemplate::new_with_options(
                binding.source_mac,
                binding.next_hop_mac,
                binding.link_type,
                mods,
            ),
            source_ipv6: nic.source_ipv6,
            icmp: IcmpEchoTemplate::new(
                binding.source_mac,
                binding.next_hop_mac,
                binding.link_type,
                mods.ttl,
            ),
            udp: UdpTemplate::new(
                binding.source_mac,
                binding.next_hop_mac,
                binding.link_type,
                mods.ttl,
            ),
            sctp: SctpTemplate::new(
                binding.source_mac,
                binding.next_hop_mac,
                binding.link_type,
                mods.ttl,
            ),
            arp: ArpTemplate::new(binding.source_mac),
            payloads: payloads.clone(),
            ip_me0: binding.source_ipv4,
            ipv4_mask: nic.source_ipv4_last - binding.source_ipv4,
            first,
            // main.c:183-186: port_mask = last - first.
            port_mask: u32::from(last - first),
            entropy: seed,
        })
    }

    fn fill(
        &self,
        p: &mut Probe,
        i: u64,
        repeats: u64,
        xxx: u64,
        ip_them: u32,
        port_them: u32,
    ) -> Result<(), PlanError> {
        p.target = TargetIp::V4(ip_them);
        let ipv4_mask = self.ipv4_mask;
        let (ip_me, port_me) = if ipv4_mask != 0 || self.port_mask != 0 {
            let n = i.wrapping_add(repeats);
            // main.c:379-384.
            let ck = syn_cookie_ipv4(
                n as u32,
                (n >> 32) as u32,
                xxx as u32,
                (xxx >> 32) as u32,
                self.entropy,
            );
            (
                self.ip_me0.wrapping_add(((ck >> 16) as u32) & ipv4_mask),
                u32::from(self.first).wrapping_add(ck as u32 & self.port_mask),
            )
        } else {
            (self.ip_me0, u32::from(self.first))
        };
        if port_them == TEMPL_ARP {
            // templ-pkt.c:914-928: у ARP нет ни порта, ни cookie в кадре, только `spa = ip_me` и `tpa = ip_them`.
            // Cookie и порт источника считаются как у остальных (main.c:389), чтобы поток источников адаптера
            // не зависел от типа скана; в кадр они не попадают.
            let port_me16 = u16::try_from(port_me)
                .map_err(|_| PlanError::PortDoesNotFit { port_them, port_me })?;
            let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, self.entropy) as u32;
            self.arp.build_arp(ip_them, ip_me, &mut p.frame);
            p.index = i;
            p.ip_me = ip_me;
            p.port_me = port_me16;
            p.ip_them = ip_them;
            p.port_them = 0;
            p.port_index = port_them;
            p.seqno = seqno;
            return Ok(());
        }
        if port_them == TEMPL_ICMP_ECHO {
            // main.c:389 даёт seqno с реальным port_me: он идёт только в ip_id (templ-pkt.c:942); [id|seq] кадра
            // это cookie с port_me = 0 (templ-pkt.c:1067), его считает `build_echo`.
            let port_me16 = u16::try_from(port_me)
                .map_err(|_| PlanError::PortDoesNotFit { port_them, port_me })?;
            let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, self.entropy) as u32;
            self.icmp
                .build_echo(ip_them, ip_me, seqno, self.entropy, &mut p.frame);
            p.index = i;
            p.ip_me = ip_me;
            p.port_me = port_me16;
            p.ip_them = ip_them;
            // у ICMP порта получателя нет: индекс 196608 в u16 не помещается, как в кадре его нет вовсе
            p.port_them = 0;
            p.port_index = port_them;
            p.seqno = seqno;
            return Ok(());
        }
        if (TEMPL_UDP..=TEMPL_UDP_LAST).contains(&port_them) {
            // templ-pkt.c:903-906: порт в кадре 16-битный (`port_them &= 0xFFFF`), а cookie (main.c:389) берётся по
            // индексу `Templ_UDP + порт`. Нагрузка ищется по порту; нет записи - 0 байт.
            let port16 = (port_them & 0xFFFF) as u16;
            let port_me16 = u16::try_from(port_me)
                .map_err(|_| PlanError::PortDoesNotFit { port_them, port_me })?;
            let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, self.entropy) as u32;
            self.udp.build_udp(
                (ip_them, port16),
                (ip_me, port_me16),
                seqno,
                self.payloads.get(port16),
                &mut p.frame,
            );
            p.index = i;
            p.ip_me = ip_me;
            p.port_me = port_me16;
            p.ip_them = ip_them;
            p.port_them = port16;
            p.port_index = port_them;
            p.seqno = seqno;
            return Ok(());
        }
        if (TEMPL_SCTP..=TEMPL_SCTP_LAST).contains(&port_them) {
            // templ-pkt.c:907-910: порт в кадре 16-битный (`port_them &= 0xFFFF`), cookie (main.c:389) берётся по
            // индексу `Templ_SCTP + порт`; он же идёт в initiate_tag INIT, а приёмник сверяет с ним verification tag.
            let port16 = (port_them & 0xFFFF) as u16;
            let port_me16 = u16::try_from(port_me)
                .map_err(|_| PlanError::PortDoesNotFit { port_them, port_me })?;
            let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, self.entropy) as u32;
            self.sctp
                .build_init((ip_them, port16), (ip_me, port_me16), seqno, &mut p.frame);
            p.index = i;
            p.ip_me = ip_me;
            p.port_me = port_me16;
            p.ip_them = ip_them;
            p.port_them = port16;
            p.port_index = port_them;
            p.seqno = seqno;
            return Ok(());
        }
        let (Ok(port_them16), Ok(port_me16)) = (u16::try_from(port_them), u16::try_from(port_me))
        else {
            return Err(PlanError::PortDoesNotFit { port_them, port_me });
        };
        // main.c:389/:402: seqno = (unsigned)cookie.
        let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, self.entropy) as u32;
        self.tmpl
            .build_syn(ip_them, port_them16, ip_me, port_me16, seqno, &mut p.frame);
        p.index = i;
        p.ip_me = ip_me;
        p.port_me = port_me16;
        p.ip_them = ip_them;
        p.port_them = port_them16;
        p.port_index = port_them;
        p.seqno = seqno;
        Ok(())
    }
}

impl Builder {
    /// Ветка IPv6 передающего цикла (main.c:336-353): `ip_me = src.ipv6`, `port_me = src.port` (первый порт
    /// диапазона, ротации нет), `cookie = syn_cookie_ipv6(ip_them, port_them, ip_me, port_me, entropy)`,
    /// `seqno = (unsigned)cookie` (:355). Только TCP (R3): порт с протокольным смещением (`U:`, `S:`, `I:`) это
    /// отказ, а не кадр.
    fn fill_v6(
        &self,
        p: &mut Probe,
        i: u64,
        ip_them: u128,
        port_them: u32,
    ) -> Result<(), PlanError> {
        let ip_me = self.source_ipv6.ok_or(PlanError::NoSourceIpv6)?;
        let port_them16 = u16::try_from(port_them).map_err(|_| PlanError::PortNotTcp(port_them))?;
        let port_me = self.first;
        let seqno =
            syn_cookie_ipv6(ip_them, port_them, ip_me, u32::from(port_me), self.entropy) as u32;
        self.tmpl6
            .build_syn(ip_them, port_them16, ip_me, port_me, seqno, &mut p.frame);
        p.target = TargetIp::V6(ip_them);
        p.index = i;
        // Поля IPv4 у зонда IPv6 нулевые: адреса лежат в `target` и в кадре.
        p.ip_me = 0;
        p.ip_them = 0;
        p.port_me = port_me;
        p.port_them = port_them16;
        p.port_index = port_them;
        p.seqno = seqno;
        Ok(())
    }
}

/// Поток probe этапа 1 без сети: те же индексы, что в C (`transmit_scan`),
/// SYN-cookie и порт источника как main.c:373-393. Сохраняет retries и shard
/// из `eff`. Резюме-поля `eff` применяются как в C.
///
/// Callback получает один переиспользуемый [`Probe`]. `Break(b)` останавливает
/// обход сразу и возвращается как `Ok(Break(b))`.
pub fn for_each_probe<B>(
    eff: &EffectiveConfig,
    binding: &AdapterBinding,
    f: impl FnMut(&Probe) -> ControlFlow<B>,
) -> Result<ControlFlow<B>, PlanError> {
    for_each_probe_nic(eff, &NicBinding::from(binding.clone()), f)
}

/// [`for_each_probe`] для адаптера CLI: с диапазоном адресов источника и флагом 17 портов. Параметры зонда
/// (`--ttl`, `--badsum`, опции TCP) берутся из `eff`.
pub fn for_each_probe_nic<B>(
    eff: &EffectiveConfig,
    nic: &NicBinding,
    f: impl FnMut(&Probe) -> ControlFlow<B>,
) -> Result<ControlFlow<B>, PlanError> {
    for_each_probe_nic_with_payloads(eff, nic, &PayloadTable::builtin(), f)
}

/// [`for_each_probe_nic`] с таблицей нагрузок UDP, собранной из `--nmap-payloads` и `--pcap-payloads`.
pub fn for_each_probe_nic_with_payloads<B>(
    eff: &EffectiveConfig,
    nic: &NicBinding,
    payloads: &PayloadTable,
    mut f: impl FnMut(&Probe) -> ControlFlow<B>,
) -> Result<ControlFlow<B>, PlanError> {
    let builder = Builder::from_nic(
        nic,
        eff.seed(),
        &eff.packet_modifiers(),
        &Arc::new(payloads.clone()),
    )?;
    let mut probe = Probe::default();
    let flow = transmit_scan_flow(
        eff.massip(),
        eff.seed(),
        eff.blackrock_rounds(),
        eff.shard(),
        1,
        0,
        eff.resume_index(),
        eff.resume_count(),
        eff.retries(),
        eff.max_rate(),
        |i, repeats, xxx, ip_them, port_them| {
            if let Err(e) = builder.fill(&mut probe, i, repeats, xxx, ip_them, port_them) {
                return ControlFlow::Break(Err(e));
            }
            match f(&probe) {
                ControlFlow::Break(b) => ControlFlow::Break(Ok(b)),
                ControlFlow::Continue(()) => ControlFlow::Continue(()),
            }
        },
    )?;
    match flow {
        ControlFlow::Continue(()) => Ok(ControlFlow::Continue(())),
        ControlFlow::Break(Ok(b)) => Ok(ControlFlow::Break(b)),
        ControlFlow::Break(Err(e)) => Err(e),
    }
}

#[derive(Debug)]
struct PlanInner {
    effective: EffectiveConfig,
    nics: Vec<NicBinding>,
    range: u64,
    blackrock: BlackRock,
    /// По одному на адаптер (у каждого свои адреса и порты источника).
    builders: Vec<Builder>,
    /// Таблица нагрузок UDP, общая у всех адаптеров.
    payloads: Arc<PayloadTable>,
}

/// Проверка портов плана CLI (спека Р1, решение R1): живой скан и
/// `--offline --packet-trace` не шлют сырые IP-протоколы (`O:*`, в C нет
/// отправки: templ-pkt.c:932) и ICMP кроме Echo (в C нет приёма `I:1`:
/// proto-icmp.c:222). `Templ_ARP` = 65536*3+2 (`I:2`, massip-port.h:18-20)
/// допустим, но только единственным портом. Диапазон сообщается по
/// наименьшему недопустимому индексу.
pub fn check_cli_ports(ports: &RangeList) -> Result<(), PlanError> {
    let allowed = |i: u32| i == TEMPL_ICMP_ECHO || i == TEMPL_ARP;
    for r in ports.as_slice() {
        if r.end < TEMPL_ICMP_ECHO {
            continue;
        }
        let mut i = r.begin.max(TEMPL_ICMP_ECHO);
        while i <= r.end && allowed(i) {
            i += 1;
        }
        if i > r.end {
            continue;
        }
        return Err(if (TEMPL_OPROTO_FIRST..=TEMPL_OPROTO_LAST).contains(&i) {
            PlanError::OprotoNotSupported(i)
        } else {
            PlanError::IcmpTypeNotSupported(i)
        });
    }
    let has_arp = is_arp_scan_ports(ports);
    if has_arp && ports.count() != 1 {
        return Err(PlanError::ArpMixedWithPorts);
    }
    Ok(())
}

/// Список портов задаёт ARP-скан: в нём есть `Templ_ARP`. Смесь с другими портами отклоняет [`check_cli_ports`]
/// (`FAIL: cannot arpscan and portscan at the same time`, main.c:1224-1229). Как в C, `-p I:2` без `--arp` это тоже
/// ARP-скан (решение R1).
pub fn is_arp_scan_ports(ports: &RangeList) -> bool {
    ports.is_contains(TEMPL_ARP)
}

/// Проверенный план нового запуска. Поля приватны; создать можно только через
/// [`ReadyPlan::new`] или [`ReadyPlan::new_cli`].
#[derive(Debug, Clone)]
pub struct ReadyPlan {
    inner: Arc<PlanInner>,
}

impl ReadyPlan {
    pub fn new(
        effective: EffectiveConfig,
        binding: AdapterBinding,
    ) -> Result<ReadyPlan, PlanError> {
        if effective.operation() != Operation::Scan {
            return Err(PlanError::NotScanOperation(effective.operation()));
        }
        if effective.resume_index() != 0 {
            return Err(PlanError::ResumeIndexNotAllowed(effective.resume_index()));
        }
        if let Some(c) = effective.resume_count().filter(|&c| c != 0) {
            return Err(PlanError::ResumeCountNotAllowed(c));
        }
        let shard = effective.shard();
        if shard != Shard::default() {
            return Err(PlanError::UnsupportedShard {
                one: shard.one,
                of: shard.of,
            });
        }
        if effective.retries() != 0 {
            return Err(PlanError::UnsupportedRetries(effective.retries()));
        }
        if effective.blackrock_rounds() != RUNTIME_BLACKROCK_ROUNDS {
            return Err(PlanError::UnsupportedRounds(effective.blackrock_rounds()));
        }
        // `canonical_job_bytes` не кодирует параметры зонда: один дайджест обязан давать один поток кадров.
        if effective.packet_modifiers() != PacketModifiers::default() {
            return Err(PlanError::UnsupportedPacketModifiers);
        }
        ReadyPlan::build(
            effective,
            vec![NicBinding::from(binding)],
            true,
            false,
            Arc::new(PayloadTable::builtin()),
        )
    }

    /// План CLI: любой валидный shard, retries до 999, `resume_index` и
    /// `resume_count` из конфигурации, 1..=8 адаптеров (main.c:212-223,
    /// :269-273). `ReadyPlan::new` для Студии остаётся прежним.
    pub fn new_cli(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
    ) -> Result<ReadyPlan, PlanError> {
        ReadyPlan::new_cli_with_payloads(effective, nics, PayloadTable::builtin())
    }

    /// [`ReadyPlan::new_cli`] с таблицей нагрузок UDP из `--nmap-payloads` и `--pcap-payloads` (по умолчанию
    /// встроенная таблица из 28 записей). Таблица одна на все адаптеры плана.
    pub fn new_cli_with_payloads(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
        payloads: PayloadTable,
    ) -> Result<ReadyPlan, PlanError> {
        ReadyPlan::new_cli_checked(effective, nics, true, false, Arc::new(payloads))
    }

    /// Только для тестов отказа движка: как [`ReadyPlan::new_cli`], но без проверки портов, поэтому план с
    /// портом без построителя зонда строится и курсор упирается в отказ посреди прохода. Не для рабочего кода.
    #[doc(hidden)]
    pub fn new_cli_without_port_checks(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
    ) -> Result<ReadyPlan, PlanError> {
        ReadyPlan::new_cli_checked(
            effective,
            nics,
            false,
            false,
            Arc::new(PayloadTable::builtin()),
        )
    }

    /// Как [`ReadyPlan::new_cli`], но без отказа R7 для целей IPv6: план с IPv6-целями строится, чтобы приёмник
    /// IPv6 и [`ReadyPlan::probe_v6`] можно было проверить до живого пути. `for_each_probe` и курсор всё равно
    /// отказывают IPv6 (передающий цикл IPv6 открывает T5). Не для рабочего кода: CLI и Студия строят планы только
    /// через [`ReadyPlan::new_cli`] и [`ReadyPlan::new`].
    #[doc(hidden)]
    pub fn new_cli_without_ipv6_guard(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
    ) -> Result<ReadyPlan, PlanError> {
        ReadyPlan::new_cli_checked(
            effective,
            nics,
            true,
            true,
            Arc::new(PayloadTable::builtin()),
        )
    }

    fn new_cli_checked(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
        check_ports: bool,
        allow_ipv6: bool,
        payloads: Arc<PayloadTable>,
    ) -> Result<ReadyPlan, PlanError> {
        if effective.operation() != Operation::Scan {
            return Err(PlanError::NotScanOperation(effective.operation()));
        }
        let shard = effective.shard();
        if shard.one == 0 || shard.one > shard.of {
            return Err(PlanError::InvalidShard {
                one: shard.one,
                of: shard.of,
            });
        }
        if effective.retries() > 999 {
            return Err(PlanError::TooManyRetries(effective.retries()));
        }
        if effective.blackrock_rounds() < 1 {
            return Err(PlanError::ZeroRounds(effective.blackrock_rounds()));
        }
        // Р1: O:*, I:n и смесь ARP с другими портами отклоняются навсегда.
        if check_ports {
            check_cli_ports(effective.massip().ports())?;
        }
        ReadyPlan::build(effective, nics, false, allow_ipv6, payloads)
    }

    fn build(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
        tcp_only: bool,
        allow_ipv6: bool,
        payloads: Arc<PayloadTable>,
    ) -> Result<ReadyPlan, PlanError> {
        if nics.is_empty() || nics.len() > 8 {
            return Err(PlanError::BadNicCount(nics.len()));
        }
        // R7: пока нет живого пути IPv6, цель IPv6 не принимается ни молча, ни пропуском.
        if !allow_ipv6 && effective.massip().has_ipv6_targets() {
            return Err(PlanError::Ipv6TargetsNotSupported);
        }
        let builders = nics
            .iter()
            .map(|n| {
                Builder::from_nic(
                    n,
                    effective.seed(),
                    &effective.packet_modifiers(),
                    &payloads,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Студия (`new`) принимает только TCP; план CLI проверил порты в `check_cli_ports`.
        if tcp_only
            && let Some(r) = effective
                .massip()
                .ports()
                .as_slice()
                .iter()
                .find(|r| r.end > u32::from(u16::MAX))
        {
            return Err(PlanError::PortNotTcp(r.end));
        }
        let range = effective.massip().try_range().map_err(ScanError::from)?;
        if range == 0 {
            return Err(ScanError::EmptyRange.into());
        }
        let blackrock = BlackRock::try_new(range, effective.seed(), effective.blackrock_rounds())
            .map_err(ScanError::from)?;
        Ok(ReadyPlan {
            inner: Arc::new(PlanInner {
                effective,
                nics,
                range,
                blackrock,
                builders,
                payloads,
            }),
        })
    }

    pub fn effective(&self) -> &EffectiveConfig {
        &self.inner.effective
    }

    /// ARP-скан (`--arp`, `I:2`): единственный порт плана это `Templ_ARP`. Приёмник принимает ARP-ответы только в
    /// нём (`scan_type.arp`, main.c:893), а CLI не резолвит шлюз (main-initadapter.c:170).
    pub fn is_arp_scan(&self) -> bool {
        is_arp_scan_ports(self.inner.effective.massip().ports())
    }

    /// Таблица нагрузок UDP плана.
    pub fn payloads(&self) -> &PayloadTable {
        &self.inner.payloads
    }

    /// Привязка первого адаптера (для плана `new` единственного).
    pub fn binding(&self) -> &AdapterBinding {
        &self.inner.nics[0].binding
    }

    /// Адаптеры плана по порядку `nic[0..n)`.
    pub fn nics(&self) -> &[NicBinding] {
        &self.inner.nics
    }

    /// Зонд SYN для одной цели IPv6 адаптера `nic_index` (ветка main.c:336-353, `seqno` из `syn_cookie_ipv6`).
    /// Порт цели это индекс порта: вне 16 бит (`U:`, `S:`, `I:`) отказ [`PlanError::PortNotTcp`] (R3), без
    /// `source_ipv6` у адаптера отказ [`PlanError::NoSourceIpv6`]. Цикл передачи пока не вызывает это (R7, T5).
    pub fn probe_v6(
        &self,
        nic_index: usize,
        i: u64,
        ip_them: u128,
        port_them: u32,
    ) -> Result<Probe, PlanError> {
        let builder = self
            .inner
            .builders
            .get(nic_index)
            .ok_or(PlanError::NicIndexOutOfRange {
                index: nic_index as u32,
                count: self.inner.builders.len(),
            })?;
        let mut p = Probe::default();
        builder.fill_v6(&mut p, i, ip_them, port_them)?;
        Ok(p)
    }

    /// Число probe плана (комбинации IP/порт).
    pub fn range(&self) -> u64 {
        self.inner.range
    }

    /// Смещение потока адаптера в базе `resume.index`:
    /// `(shard.one - 1) * nic_count + nic_index` (main.c:269, 32-битное произведение).
    pub fn nic_offset(&self, nic_index: u32) -> u64 {
        let one = self.inner.effective.shard().one;
        let count = self.inner.nics.len() as u32;
        u64::from(one.wrapping_sub(1).wrapping_mul(count)).wrapping_add(u64::from(nic_index))
    }

    /// Конец цикла адаптера `nic_index`, `main.c:269-273`:
    /// `min(range, start + resume_count) + retries * range`, где
    /// `start = resume_index + (shard.one - 1) * nic_count + nic_index`.
    pub fn effective_end(&self, nic_index: u32) -> u64 {
        let (_, end) = self.bounds(nic_index, self.inner.effective.resume_index());
        end
    }

    /// `(start, end)` потока адаптера при базе `resume_index` (main.c:269-273).
    fn bounds(&self, nic_index: u32, base: u64) -> (u64, u64) {
        let e = &self.inner.effective;
        let (start, end, _) = transmit_bounds(
            self.inner.range,
            e.shard(),
            self.inner.nics.len() as u32,
            nic_index,
            base,
            e.resume_count(),
            e.retries(),
        );
        (start, end)
    }

    /// Курсор потока адаптера `nic_index` (`main.c:212-223, :269-273, :328-334,
    /// :421-431`). `resume_override` заменяет `resume.index` (база, к которой
    /// C прибавляет смещение shard и NIC); `None` берёт его из конфигурации.
    pub fn cursor_for_nic(
        &self,
        nic_index: u32,
        resume_override: Option<u64>,
    ) -> Result<ProbeCursor, PlanError> {
        let count = self.inner.nics.len();
        if nic_index as usize >= count {
            return Err(PlanError::NicIndexOutOfRange {
                index: nic_index,
                count,
            });
        }
        let e = &self.inner.effective;
        let range = self.inner.range;
        let base = resume_override.unwrap_or_else(|| e.resume_index());
        // C проверки не делает (main.c:269-280); возобновление на хвосте
        // повторов (range < base < конец) законно. Предел: `(retries+1)*range`,
        // при retries == 0 это `range` (путь v1 и engine.rs:760).
        let limit = range.saturating_add(u64::from(e.retries()).saturating_mul(range));
        if base > limit {
            return Err(PlanError::NextIndexBeyondRange {
                next_index: base,
                limit,
            });
        }
        let (start, end) = self.bounds(nic_index, base);
        let stream = transmit_index_stream(
            range,
            e.shard(),
            count as u32,
            nic_index,
            base,
            e.resume_count(),
            e.retries(),
            e.max_rate(),
        );
        let stream: Box<dyn Iterator<Item = (u64, u64)> + Send> = Box::new(stream);
        let mut cursor = ProbeCursor {
            plan: self.clone(),
            nic_index: nic_index as usize,
            stream: stream.peekable(),
            loaded: VecDeque::new(),
            ended: false,
            failed: None,
            blackrock: self.inner.blackrock,
            repeats: 0,
            position: start,
            end,
        };
        cursor.refresh_position();
        Ok(cursor)
    }
}

/// Курсор по probe плана: `current` и `preload` не продвигают, `advance_sent`
/// подтверждает ровно одну успешную отправку, `advance_sent_n` первые `k`
/// загруженных.
pub struct ProbeCursor {
    plan: ReadyPlan,
    nic_index: usize,
    stream: Peekable<Box<dyn Iterator<Item = (u64, u64)> + Send>>,
    /// Загруженные, ещё не подтверждённые probe, по порядку индексов.
    loaded: VecDeque<Probe>,
    /// Поток кончился или probe не построился: новых probe нет. Липкий, чтобы
    /// пропущенный индекс не сдвинул последовательность.
    ended: bool,
    /// Probe не построился: конец не естественный, `--infinite` не перезапускает проход, а движок обязан
    /// объявить отказ ([`ProbeCursor::build_error`]).
    failed: Option<PlanError>,
    /// Перестановка текущего прохода: у прохода `n` это `BlackRock(seed + n)` (`main.c:225-228, 445-449`), у
    /// прохода 0 перестановка плана.
    blackrock: BlackRock,
    /// Счётчик `--infinite` (`repeats` в C): номер прохода, входит в `(unsigned)(i + repeats)` (`main.c:379`).
    repeats: u64,
    /// Внешний индекс `i` следующего неподтверждённого probe (main.c:431
    /// `parms->my_index = i`), не число отправленных кадров.
    position: u64,
    /// `effective_end` потока: позиция после последнего кадра.
    end: u64,
}

impl std::fmt::Debug for ProbeCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeCursor")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl ProbeCursor {
    /// Курсор, начинающийся с индекса `next_index` (0 для нового запуска).
    /// При `retries == 0`: `next_index == range` даёт пустой курсор, `> range`
    /// ошибка. При `retries > 0` пределом служит `(retries + 1) * range`.
    pub fn new(plan: &ReadyPlan, next_index: u64) -> Result<ProbeCursor, PlanError> {
        plan.cursor_for_nic(0, Some(next_index))
    }

    /// Нормализованная база возобновления: `position()` без смещения shard/NIC,
    /// то есть значение для `cursor_for_nic(nic, Some(base))` (смещение
    /// прибавляется внутри, повторно его учитывать не нужно).
    pub fn resume_base(&self) -> u64 {
        self.position
            .saturating_sub(self.plan.nic_offset(self.nic_index as u32))
    }

    /// Ставит `position` по внешнему индексу: голова загруженных, иначе
    /// следующий `i` потока, иначе `end`.
    fn refresh_position(&mut self) {
        self.position = match self.loaded.front() {
            Some(p) => p.index,
            None => match self.stream.peek() {
                Some(&(i, _)) => i,
                None => self.end,
            },
        };
    }

    /// Строит следующий probe потока и ставит его в хвост загруженных. `false`
    /// в конце диапазона.
    fn load_one(&mut self) -> bool {
        if self.ended {
            return false;
        }
        let Some((i, x)) = self.stream.next() else {
            self.ended = true;
            return false;
        };
        let inner = &*self.plan.inner;
        let builder = &inner.builders[self.nic_index];
        let xxx = self.blackrock.shuffle(x);
        // main.c:336-373; цели IPv6 план не пропускает (`Ipv6TargetsNotSupported`), `V6` тут нарушение.
        let (target, port, xxx) = inner.effective.massip().pick_transmit(xxx);
        let TargetIp::V4(ip) = target else {
            self.ended = true;
            self.failed = Some(PlanError::Ipv6TargetsNotSupported);
            return false;
        };
        let mut p = Probe::default();
        // `ReadyPlan::new` и `new_cli` отклоняют порты без построителя заранее, поэтому отказ здесь это
        // нарушение инварианта. Он не паникует и не выдаётся за конец скана: курсор останавливается и хранит
        // причину, а движок завершает запуск отказом.
        match builder.fill(&mut p, i, self.repeats, xxx, ip, port) {
            Ok(()) => {
                self.loaded.push_back(p);
                true
            }
            Err(e) => {
                self.ended = true;
                self.failed = Some(e);
                false
            }
        }
    }

    /// Причина, по которой probe не построился. `Some` означает, что конец курсора не естественный.
    pub fn build_error(&self) -> Option<PlanError> {
        self.failed
            .clone()
            .map(|e| PlanError::ProbeBuild(Box::new(e)))
    }

    /// Номер прохода `--infinite` (0 для первого).
    pub fn repeats(&self) -> u64 {
        self.repeats
    }

    /// Следующий проход `--infinite` (`main.c:445-449` `seed++; repeats++; goto infinite`, метка на `:251`).
    /// Только когда `effective.infinite()` включён и текущий проход дошёл до `effective_end` (поток исчерпан и всё
    /// отправлено): тогда пересоздаёт `BlackRock::new(range, seed + repeats + 1, rounds)` (`:262`), увеличивает
    /// `repeats` и сбрасывает поток на начало (`:269-273`) с базой 0 и без `resume-count`: оба параметра действуют
    /// только на первом проходе (спец Р5). Это сознательное отличие от C: метка `:251` стоит до
    /// `start = resume.index + ...`, и C повторяет окно на каждом проходе. Здесь следующие проходы покрывают весь
    /// диапазон `[0, range)` и повторы. `end` пересчитывается для нового прохода.
    /// `entropy` построителя остаётся исходным `seed` (`:227` `entropy = masscan->seed` задан до метки), поэтому
    /// `seqno` и порт источника проверяются приёмом для обоих проходов. `true`, если проход начат заново.
    pub fn advance_pass(&mut self) -> bool {
        let e = self.plan.effective();
        if !e.infinite()
            || self.failed.is_some()
            || !self.loaded.is_empty()
            || self.stream.peek().is_some()
        {
            return false;
        }
        let inner = &*self.plan.inner;
        let next = self.repeats.wrapping_add(1);
        let Ok(blackrock) = BlackRock::try_new(
            inner.range,
            e.seed().wrapping_add(next),
            e.blackrock_rounds(),
        ) else {
            return false;
        };
        let stream = transmit_index_stream(
            inner.range,
            e.shard(),
            inner.nics.len() as u32,
            self.nic_index as u32,
            0,
            None,
            e.retries(),
            e.max_rate(),
        );
        let (_, end, _) = transmit_bounds(
            inner.range,
            e.shard(),
            inner.nics.len() as u32,
            self.nic_index as u32,
            0,
            None,
            e.retries(),
        );
        let stream: Box<dyn Iterator<Item = (u64, u64)> + Send> = Box::new(stream);
        let mut stream = stream.peekable();
        // Пустой проход не перезапускается: движок крутился бы вхолостую.
        if stream.peek().is_none() {
            return false;
        }
        self.stream = stream;
        self.end = end;
        self.blackrock = blackrock;
        self.repeats = next;
        self.ended = false;
        self.refresh_position();
        true
    }

    /// Текущий неподтверждённый probe; повторный вызов не продвигает.
    /// `None` в конце диапазона.
    pub fn current(&mut self) -> Option<&Probe> {
        if self.loaded.is_empty() {
            self.load_one();
        }
        self.loaded.front()
    }

    /// Загружает до `n` ещё не подтверждённых probe (начиная с текущего) и
    /// отдаёт их по порядку индексов. Не продвигает `position`; повторный вызов
    /// отдаёт те же probe. Короче `n` только в конце диапазона.
    /// Вызывающий ограничивает `n` (движок: `MAX_TX_BATCH`): внутреннего предела нет.
    pub fn preload(&mut self, n: usize) -> &[Probe] {
        while self.loaded.len() < n && self.load_one() {}
        let slice = self.loaded.make_contiguous();
        &slice[..n.min(slice.len())]
    }

    /// Подтверждает ровно один успешно отправленный текущий probe. В конце
    /// диапазона ничего не делает.
    pub fn advance_sent(&mut self) {
        if self.current().is_some() {
            self.advance_sent_n(1);
        }
    }

    /// Подтверждает `k` первых загруженных probe; `position` идёт по внешнему индексу. `k` больше
    /// числа загруженных это ошибка вызывающего (debug assert); в release
    /// подтверждается столько, сколько загружено.
    pub fn advance_sent_n(&mut self, k: usize) {
        debug_assert!(
            k <= self.loaded.len(),
            "advance_sent_n({k}) beyond the {} loaded probes",
            self.loaded.len()
        );
        let k = k.min(self.loaded.len());
        self.loaded.drain(..k);
        self.refresh_position();
    }

    /// Следующий неподтверждённый индекс.
    pub fn position(&self) -> u64 {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScanConfig, validate};
    use crate::massip::MassIp;
    use crate::targets::{add_target_string, parse_ports};
    use std::collections::BTreeSet;

    const IP_ME: u32 = 0x0aff_0001;
    const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    fn binding() -> AdapterBinding {
        AdapterBinding {
            interface_id: "test0".to_string(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: MAC_ME,
            next_hop_mac: MAC_NH,
            source_ports: (40000, 40003),
        }
    }

    fn nics(n: u32) -> Vec<NicBinding> {
        (0..n)
            .map(|k| {
                let mut b = binding();
                b.interface_id = format!("test{k}");
                NicBinding::from(b)
            })
            .collect()
    }

    fn eff(targets: &str, ports: &str, f: impl FnOnce(&mut ScanConfig)) -> EffectiveConfig {
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), targets).unwrap();
        parse_ports(m.ports_mut(), ports).unwrap();
        let mut cfg = ScanConfig {
            targets: m,
            seed: 0x1234_5678,
            ..ScanConfig::default()
        };
        f(&mut cfg);
        validate(&cfg, Operation::Scan).unwrap()
    }

    fn drain(cursor: &mut ProbeCursor) -> Vec<Probe> {
        let mut out = Vec::new();
        while let Some(p) = cursor.current().cloned() {
            out.push(p);
            cursor.advance_sent();
        }
        out
    }

    fn oracle(e: &EffectiveConfig) -> Vec<Probe> {
        let mut out = Vec::new();
        let flow = for_each_probe(e, &binding(), |p| {
            out.push(p.clone());
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        out
    }

    // 37 целей: 198.18.0.0-198.18.0.36 x порт 80 (простой range, не кратный шагу).
    const T37: &str = "198.18.0.0-198.18.0.36";

    #[test]
    fn shards_partition_full_range_without_gaps_or_overlaps() {
        let all = oracle(&eff(T37, "80", |_| {}));
        assert_eq!(all.len(), 37);
        let want: BTreeSet<_> = all.iter().map(|p| (p.ip_them, p.port_them)).collect();
        assert_eq!(want.len(), 37);
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for one in 1..=3 {
            let e = eff(T37, "80", |c| c.shard = Shard { one, of: 3 });
            let want_shard = oracle(&e);
            let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
            let got = drain(&mut plan.cursor_for_nic(0, None).unwrap());
            assert_eq!(got, want_shard, "shard {one}/3 differs from for_each_probe");
            total += got.len();
            for p in got {
                assert!(seen.insert((p.ip_them, p.port_them)), "overlap {p:?}");
            }
        }
        assert_eq!(total, 37);
        assert_eq!(seen, want);
    }

    #[test]
    fn shards_partition_multi_port_range_with_cartesian_excludes() {
        let mut t = MassIp::new();
        add_target_string(t.ipv4_mut(), "198.18.0.0/29").unwrap();
        parse_ports(t.ports_mut(), "80-84").unwrap();
        let mut ex = MassIp::new();
        add_target_string(ex.ipv4_mut(), "198.18.0.5-198.18.0.7").unwrap();
        t.apply_excludes(&mut ex);
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for one in 1..=3 {
            let cfg = ScanConfig {
                targets: t.clone(),
                seed: 0x1234_5678,
                shard: Shard { one, of: 3 },
                ..ScanConfig::default()
            };
            let plan =
                ReadyPlan::new_cli(validate(&cfg, Operation::Scan).unwrap(), nics(1)).unwrap();
            assert_eq!(plan.range(), 25);
            for p in drain(&mut plan.cursor_for_nic(0, None).unwrap()) {
                total += 1;
                assert!(seen.insert((p.ip_them, p.port_them)), "overlap {p:?}");
            }
        }
        assert_eq!(total, 25);
        assert_eq!(seen.len(), 25);
        let ports: BTreeSet<_> = seen.iter().map(|&(_, port)| port).collect();
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn resume_on_retry_tail_is_accepted() {
        let e = eff("198.18.0.0-198.18.0.9", "80", |c| c.retries = 2);
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        // range = 10, конец = 30: база 15 лежит на хвосте повторов.
        let mut cursor = plan.cursor_for_nic(0, Some(15)).unwrap();
        assert_eq!(cursor.position(), 15);
        assert_eq!(drain(&mut cursor).len(), (30 - 15) * 3);
        assert_eq!(cursor.position(), 30);
        assert!(matches!(
            plan.cursor_for_nic(0, Some(31)),
            Err(PlanError::NextIndexBeyondRange { .. })
        ));
        // T1 N-1: the limit is the transmit limit `(retries + 1) * range` = 30, not the scan range 10.
        assert_eq!(
            plan.cursor_for_nic(0, Some(31)).unwrap_err().to_string(),
            "next index 31 is beyond the transmit limit 30"
        );
        // retries == 0 (путь v1): `> range` по-прежнему ошибка.
        let v1 = ReadyPlan::new_cli(eff("198.18.0.0-198.18.0.9", "80", |_| {}), nics(1)).unwrap();
        assert!(ProbeCursor::new(&v1, 10).is_ok());
        assert!(ProbeCursor::new(&v1, 11).is_err());
    }

    #[test]
    fn resume_base_strips_shard_and_nic_offset() {
        let e = eff(T37, "80", |c| c.shard = Shard { one: 2, of: 3 });
        let plan = ReadyPlan::new_cli(e, nics(2)).unwrap();
        assert_eq!(plan.nic_offset(1), 3);
        let cursor = plan.cursor_for_nic(1, Some(6)).unwrap();
        assert_eq!(cursor.position(), 9);
        assert_eq!(cursor.resume_base(), 6);
        let again = plan.cursor_for_nic(1, Some(cursor.resume_base())).unwrap();
        assert_eq!(again.position(), 9);
    }

    #[test]
    fn multi_nic_and_shards_match_c_increment() {
        let mut all = BTreeSet::new();
        let mut total = 0;
        for one in 1..=3u32 {
            let e = eff(T37, "80", |c| c.shard = Shard { one, of: 3 });
            let plan = ReadyPlan::new_cli(e, nics(2)).unwrap();
            for nic in 0..2u32 {
                let idx: Vec<u64> = drain(&mut plan.cursor_for_nic(nic, None).unwrap())
                    .iter()
                    .map(|p| p.index)
                    .collect();
                // main.c:269 start = (one-1)*nic_count + nic_index, шаг main.c:223.
                let start = u64::from((one - 1) * 2 + nic);
                if one == 2 {
                    assert_eq!(idx[0], 2 + u64::from(nic));
                }
                assert_eq!(idx[0], start);
                assert!(idx.windows(2).all(|w| w[1] - w[0] == 6));
                total += idx.len();
                all.extend(idx);
            }
        }
        assert_eq!(total, 37);
        assert_eq!(all, (0..37).collect::<BTreeSet<u64>>());
    }

    #[test]
    fn retries_stream_matches_for_each_probe() {
        let e = eff("198.18.0.0-198.18.0.9", "80", |c| {
            c.retries = 2;
            c.max_rate = 7.0;
        });
        let want = oracle(&e);
        assert_eq!(want.len(), (2 + 1) * (2 + 1) * 10);
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        assert_eq!(plan.effective_end(0), 10 + 2 * 10);
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        let got = drain(&mut cursor);
        assert_eq!(got.len(), 90);
        assert_eq!(got, want);
        assert_eq!(cursor.position(), 30);
    }

    #[test]
    fn cursor_tracks_outer_index_across_retries_and_shards() {
        let e = eff("198.18.0.0-198.18.0.9", "80", |c| {
            c.retries = 2;
            c.shard = Shard { one: 1, of: 2 };
        });
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        assert_eq!(cursor.position(), 0);
        cursor.advance_sent();
        assert_eq!(cursor.position(), 0);
        cursor.advance_sent();
        assert_eq!(cursor.position(), 0);
        cursor.advance_sent();
        assert_eq!(cursor.position(), 2);
        // preload не двигает позицию; подтверждение k кадров из пачки тоже
        // считается по внешнему индексу.
        assert_eq!(cursor.preload(4).len(), 4);
        assert_eq!(cursor.position(), 2);
        cursor.advance_sent_n(2);
        assert_eq!(cursor.position(), 2);
        cursor.advance_sent_n(2);
        assert_eq!(cursor.position(), 4);
    }

    /// `--infinite` (main.c:225-228, :445-449): второй проход идёт с `seed + 1` и `repeats = 1`, а SYN-cookie
    /// остаётся на исходном `entropy`, поэтому приём подтверждает SYN-ACK обоих проходов.
    #[test]
    fn infinite_restarts_with_incremented_seed_and_constant_entropy() {
        // rate 102: `(i + rate) % range` (main.c:325-330) is `(i + 2) % 4`, so the oracle sees the rate term (at the
        // default rate 100 it vanishes, 100 = 0 mod 4).
        let e = eff("198.18.0.0-198.18.0.3", "80", |c| {
            c.seed = 10;
            c.infinite = true;
            c.max_rate = 102.0;
        });
        let rounds = e.blackrock_rounds();
        let first_oracle = oracle(&eff("198.18.0.0-198.18.0.3", "80", |c| {
            c.seed = 10;
            c.max_rate = 102.0;
        }));
        let plan = ReadyPlan::new_cli(e.clone(), nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        // Проход не закончился: перезапуска нет.
        assert!(!cursor.advance_pass());
        let mut got = Vec::new();
        for _ in 0..4 {
            let p = cursor.current().cloned().unwrap();
            got.push(p);
            cursor.advance_sent();
        }
        assert_eq!(cursor.repeats(), 0);
        assert_eq!(got, first_oracle, "pass 0 equals the seed=10 oracle");
        assert!(cursor.current().is_none());
        assert!(cursor.advance_pass());
        assert_eq!(cursor.repeats(), 1);
        assert_eq!(cursor.position(), 0);
        let second = drain(&mut cursor);
        assert_eq!(second.len(), 4);
        // Порядок целей второго прохода это BlackRock(seed = 11); `seqno` и порт источника считаются с entropy = 10,
        // а `i + repeats` (main.c:379) даёт `n = i + 1`.
        let br = BlackRock::try_new(4, 11, rounds).unwrap();
        for (i, p) in second.iter().enumerate() {
            // main.c:328: C's index is `(i + max_rate) % range` (rate 102, range 4).
            let xxx = br.shuffle((i as u64 + 102) % 4);
            let (ip, port) = e.massip().pick(xxx);
            assert_eq!((p.ip_them, u32::from(p.port_them)), (ip, port), "i={i}");
            let n = i as u64 + 1;
            let ck = syn_cookie_ipv4(n as u32, 0, xxx as u32, (xxx >> 32) as u32, 10);
            assert_eq!(u32::from(p.port_me), 40000 + (ck as u32 & 3), "i={i}");
            assert_eq!(p.ip_me, IP_ME);
            let want = syn_cookie_ipv4(ip, port, p.ip_me, u32::from(p.port_me), 10) as u32;
            assert_eq!(p.seqno, want, "i={i}: entropy stays the initial seed");
            assert_eq!(p.index, i as u64);
        }
        let order = |v: &[Probe]| v.iter().map(|p| p.ip_them).collect::<Vec<_>>();
        assert_ne!(order(&second), order(&got), "a new seed reshuffles");
        // Третий проход: seed = 12, repeats = 2.
        assert!(cursor.advance_pass());
        assert_eq!(cursor.repeats(), 2);
    }

    #[test]
    fn advance_pass_is_a_noop_without_infinite() {
        let e = eff("198.18.0.0-198.18.0.3", "80", |_| {});
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        assert_eq!(drain(&mut cursor).len(), 4);
        assert!(!cursor.advance_pass());
        assert!(cursor.current().is_none());
    }

    /// Р5: `resume-index` действует только на первом проходе, дальше проходы покрывают весь диапазон.
    #[test]
    fn infinite_later_passes_ignore_resume_index() {
        let e = eff("198.18.0.0-198.18.0.5", "80", |c| {
            c.seed = 10;
            c.infinite = true;
            c.resume_index = 4;
            c.resume_count = Some(1);
        });
        let rounds = e.blackrock_rounds();
        let plan = ReadyPlan::new_cli(e.clone(), nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        let first: Vec<u64> = drain(&mut cursor).iter().map(|p| p.index).collect();
        assert_eq!(first, [4], "pass 0 honours resume_index and resume_count");
        assert!(cursor.advance_pass());
        let second = drain(&mut cursor);
        assert_eq!(
            second.iter().map(|p| p.index).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5]
        );
        let br = BlackRock::try_new(6, 11, rounds).unwrap();
        for p in &second {
            // main.c:328 `xXx = i + r * rate`, затем по модулю range.
            let x = (p.index + e.max_rate() as u64) % 6;
            let (ip, port) = e.massip().pick(br.shuffle(x));
            assert_eq!((p.ip_them, u32::from(p.port_them)), (ip, port));
        }
        // Третий проход тоже полный.
        assert!(cursor.advance_pass());
        assert_eq!(drain(&mut cursor).len(), 6);
    }

    /// `end` нового прохода пересчитывается: после исчерпания `position()` равен его концу, а не концу прохода 0.
    #[test]
    fn infinite_restart_recomputes_the_pass_end() {
        let e = eff("198.18.0.0-198.18.0.5", "80", |c| {
            c.infinite = true;
            c.resume_index = 1;
            c.resume_count = Some(2);
        });
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        assert_eq!(drain(&mut cursor).len(), 2);
        assert_eq!(cursor.position(), 3, "pass 0 ends at resume_index + count");
        assert!(cursor.advance_pass());
        assert_eq!(drain(&mut cursor).len(), 6);
        assert_eq!(
            cursor.position(),
            6,
            "pass 1 is the full range: end = range"
        );
    }

    fn range_nic(first: u32, last: u32, ports: (u16, u16), legacy: bool) -> NicBinding {
        let mut b = binding();
        b.source_ipv4 = first;
        b.source_ports = ports;
        NicBinding {
            binding: b,
            source_ipv4_last: last,
            legacy_c_17_port_mask: legacy,
            source_ipv6: None,
        }
    }

    /// main-conf.c:2486-2550 + main.c:378-385: ширина `--adapter-ip A-B` степень двойки, источник выбирается
    /// как `first + ((ck >> 16) & (last - first))`.
    #[test]
    fn adapter_ip_power_of_two_range_rotates_source_ip() {
        const FIRST: u32 = 0xc612_0010; // 198.18.0.16
        let e = eff("198.18.1.0/26", "80", |_| {});
        let plan = ReadyPlan::new_cli(e, vec![range_nic(FIRST, FIRST + 3, (40000, 40000), false)])
            .unwrap();
        let probes = drain(&mut plan.cursor_for_nic(0, None).unwrap());
        assert_eq!(probes.len(), 64);
        let mut seen = BTreeSet::new();
        for p in &probes {
            assert!((FIRST..=FIRST + 3).contains(&p.ip_me), "{:#x}", p.ip_me);
            assert_eq!(&p.frame[26..30], &p.ip_me.to_be_bytes());
            seen.insert(p.ip_me);
        }
        assert_eq!(seen.len(), 4, "all four addresses are used: {seen:?}");
        // Независимо от `fill`: тот же индекс через for_each_probe с тем же ключом даёт тот же адрес.
        let nic = range_nic(FIRST, FIRST + 3, (40000, 40000), false);
        let mut via_oracle = Vec::new();
        let flow = for_each_probe_nic(&eff("198.18.1.0/26", "80", |_| {}), &nic, |p| {
            via_oracle.push(p.ip_me);
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(
            via_oracle,
            probes.iter().map(|p| p.ip_me).collect::<Vec<_>>()
        );

        // Ширина 3 не степень двойки: отказ (main-conf.c:2483), как и `last < first`.
        for (first, last) in [(FIRST, FIRST + 2), (FIRST + 3, FIRST), (FIRST, FIRST + 5)] {
            let err = ReadyPlan::new_cli(
                eff("198.18.1.0/26", "80", |_| {}),
                vec![range_nic(first, last, (40000, 40000), false)],
            )
            .unwrap_err();
            assert_eq!(err, PlanError::InvalidSourceIpv4 { first, last });
        }
        // Одиночный адрес и ширина 2, 8, 256 допустимы.
        for width in [1u32, 2, 8, 256] {
            ReadyPlan::new_cli(
                eff("198.18.1.0/26", "80", |_| {}),
                vec![range_nic(FIRST, FIRST + width - 1, (40000, 40000), false)],
            )
            .unwrap();
        }
    }

    /// Спека Р6: поблажка C только для `last - first == 16` (17 портов, main.c:1318), и только у адаптера,
    /// которому её выдали; порядок адаптеров не влияет.
    #[test]
    fn legacy_17_port_leniency_is_exactly_seventeen_ports_and_per_nic() {
        let plan =
            |nics: Vec<NicBinding>| ReadyPlan::new_cli(eff("198.18.1.0/30", "80", |_| {}), nics);
        let port_err = |first: u16, last: u16| PlanError::InvalidSourcePorts { first, last };

        // С флагом: ровно 17 портов проходят, ширины 15 и 20 нет.
        plan(vec![range_nic(IP_ME, IP_ME, (40000, 40016), true)]).unwrap();
        for last in [40014u16, 40019, 40017, 40004, 40030] {
            assert_eq!(
                plan(vec![range_nic(IP_ME, IP_ME, (40000, last), true)]).unwrap_err(),
                port_err(40000, last),
                "width {} under the flag",
                last - 40000 + 1
            );
        }
        // Без флага 17 портов отклоняются; ширина 16 (степень двойки) проходит всегда.
        assert_eq!(
            plan(vec![range_nic(IP_ME, IP_ME, (40000, 40016), false)]).unwrap_err(),
            port_err(40000, 40016)
        );
        plan(vec![range_nic(IP_ME, IP_ME, (40000, 40015), false)]).unwrap();
        plan(vec![range_nic(IP_ME, IP_ME, (40000, 40015), true)]).unwrap();

        // Флаг принадлежит адаптеру: у соседа без флага те же 17 портов отклоняются при любом порядке.
        let with = range_nic(IP_ME, IP_ME, (40000, 40016), true);
        let without = range_nic(IP_ME, IP_ME, (40000, 40016), false);
        for nics in [
            vec![with.clone(), without.clone()],
            vec![without.clone(), with.clone()],
        ] {
            assert_eq!(plan(nics).unwrap_err(), port_err(40000, 40016));
        }
        plan(vec![with.clone(), with]).unwrap();
    }

    /// `--ttl`, `--badsum` и опции TCP из конфигурации попадают в кадры плана и в оракул `for_each_probe`.
    #[test]
    fn plan_applies_ttl_badsum_and_tcp_options_from_the_config() {
        use crate::packet::TcpHeaderOptions;
        let e = eff("198.18.1.0/30", "80", |c| {
            c.ttl = Some(64);
            c.badsum = true;
            c.tcp_opts = TcpHeaderOptions {
                mss: Some(1400),
                sackok: true,
                wscale: Some(7),
                tsecho: Some(0xdead_beef),
            };
        });
        let plan = ReadyPlan::new_cli(e.clone(), nics(1)).unwrap();
        let from_plan = drain(&mut plan.cursor_for_nic(0, None).unwrap());
        let from_oracle = oracle(&e);
        assert_eq!(from_plan.len(), 4);
        for (a, b) in from_plan.iter().zip(&from_oracle) {
            assert_eq!(a.frame, b.frame);
            assert_eq!(a.frame[22], 64);
            assert_eq!(a.frame[46] >> 4, 10, "doff");
            assert_eq!(&a.frame[54..62], &[2, 4, 5, 0x78, 4, 2, 3, 3]);
            assert_eq!(a.frame.len(), 74);
            assert_eq!(
                crate::checksum::ip_header_checksum(&a.frame, 14, 34),
                0xffff
            );
        }
        // Студия (`new`) принимает только умолчание; CLI (`new_cli`) применяет параметры.
        let non_default = eff("198.18.1.0/30", "80", |c| c.ttl = Some(64));
        assert_eq!(
            ReadyPlan::new(non_default.clone(), binding()).unwrap_err(),
            PlanError::UnsupportedPacketModifiers
        );
        ReadyPlan::new(eff("198.18.1.0/30", "80", |_| {}), binding()).unwrap();
        let cli = ReadyPlan::new_cli(non_default, nics(1)).unwrap();
        let p = drain(&mut cli.cursor_for_nic(0, None).unwrap());
        assert!(p.iter().all(|p| p.frame[22] == 64));
        // Умолчание не меняет кадр.
        let d = oracle(&eff("198.18.1.0/30", "80", |_| {}));
        assert!(d.iter().all(|p| p.frame.len() == 58 && p.frame[22] == 255));
    }

    fn cli_err(ports: &str) -> PlanError {
        ReadyPlan::new_cli(eff("198.18.2.0/30", ports, |_| {}), nics(1)).unwrap_err()
    }

    #[test]
    fn sticky_port_prefixes_and_oproto_live_refusal() {
        // Р1/R1/R3: O:* и I:n (кроме I:0 и ARP = I:2) отклоняются планом CLI.
        for ports in ["O:47", "o:0", "O:255", "T:80,O:47", "U:53,O:1-3"] {
            assert!(
                matches!(cli_err(ports), PlanError::OprotoNotSupported(_)),
                "{ports}"
            );
        }
        for ports in [
            "I:1", "I:3", "I:255", "I:0-1", "S:1,I:1", "I:0-300", "I:512",
        ] {
            assert!(
                matches!(cli_err(ports), PlanError::IcmpTypeNotSupported(_)),
                "{ports}"
            );
        }
        // O:47 это I:303 (тот же индекс 196911): оба отказа текстом называют индекс
        assert_eq!(cli_err("I:303"), PlanError::OprotoNotSupported(196_911));
        assert_eq!(cli_err("I:1"), PlanError::IcmpTypeNotSupported(196_609));
        assert!(cli_err("I:1").to_string().contains("I:1"));
        assert!(cli_err("O:47").to_string().contains("O:47"));
        // Постоянная проверка принимает I:0 и ARP (I:2) как допустимые порты; ARP только единственным
        let ok = |ports: &str| {
            let e = eff("198.18.2.0/30", ports, |_| {});
            check_cli_ports(e.massip().ports())
        };
        assert_eq!(ok("I:0"), Ok(()));
        assert_eq!(ok("I:2"), Ok(()));
        assert_eq!(ok("U:53,S:2905,I:0,T:80"), Ok(()));
        assert_eq!(ok("80,O:47"), Err(PlanError::OprotoNotSupported(196_911)));
        for ports in ["I:2,T:80", "I:2,U:53", "I:0,I:2"] {
            assert_eq!(ok(ports), Err(PlanError::ArpMixedWithPorts), "{ports}");
        }
        assert_eq!(ok("I:2-3"), Err(PlanError::IcmpTypeNotSupported(196_611)));
        // new_cli: смесь с ARP отказывает тем же `ArpMixedWithPorts`
        assert_eq!(cli_err("I:2,T:80"), PlanError::ArpMixedWithPorts);
        assert_eq!(cli_err("I:0,I:2"), PlanError::ArpMixedWithPorts);
        // Студия: `new` по-прежнему только TCP
        for ports in ["U:53", "S:1", "I:0"] {
            assert!(matches!(
                ReadyPlan::new(eff("198.18.2.0/30", ports, |_| {}), binding()).unwrap_err(),
                PlanError::PortNotTcp(_)
            ));
        }
    }

    #[test]
    fn icmp_echo_plan_builds_through_the_cli_path_and_splits_across_nics() {
        // I:0 больше не отказывает: 90-байтные кадры, ip_id и [id|seq] как у C; адаптеры делят поток по чётности
        let e = || eff("198.18.2.0/30", "I:0", |_| {});
        let one = ReadyPlan::new_cli(e(), nics(1)).unwrap();
        let all = drain(&mut one.cursor_for_nic(0, None).unwrap());
        assert_eq!(all.len(), 4);
        for p in &all {
            assert_eq!(p.frame.len(), 90);
            assert_eq!(p.frame[23], 1, "proto ICMP");
            assert_eq!(p.port_them, 0);
            let id_seq = u32::from_be_bytes(p.frame[38..42].try_into().unwrap());
            assert_eq!(
                id_seq,
                crate::cookie::icmp_echo_cookie(p.ip_them, p.ip_me, 0x1234_5678)
            );
        }
        let two = ReadyPlan::new_cli(e(), nics(2)).unwrap();
        let k0 = drain(&mut two.cursor_for_nic(0, None).unwrap());
        let k1 = drain(&mut two.cursor_for_nic(1, None).unwrap());
        assert_eq!(
            k0.iter().map(|p| p.index).collect::<Vec<_>>(),
            [0, 2],
            "even outer indices"
        );
        assert_eq!(k1.iter().map(|p| p.index).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(
            [
                k0[0].frame.clone(),
                k1[0].frame.clone(),
                k0[1].frame.clone(),
                k1[1].frame.clone()
            ],
            [
                all[0].frame.clone(),
                all[1].frame.clone(),
                all[2].frame.clone(),
                all[3].frame.clone()
            ],
            "same source address on both test NICs: the split reproduces the single stream"
        );
        // Смешанный список: ICMP и TCP в одном потоке без ошибок сборки
        let mixed = ReadyPlan::new_cli(eff("198.18.2.0/30", "80,I:0", |_| {}), nics(1)).unwrap();
        let mut cur = mixed.cursor_for_nic(0, None).unwrap();
        let frames = drain(&mut cur);
        assert!(cur.build_error().is_none());
        assert_eq!(frames.iter().filter(|p| p.frame.len() == 90).count(), 4);
        assert_eq!(frames.iter().filter(|p| p.frame.len() == 58).count(), 4);
    }

    #[test]
    fn arp_plan_builds_and_unbuildable_ports_still_fail_the_run() {
        // Временной таблицы отказов больше нет: чистый ARP, TCP, UDP, SCTP и ICMP Echo проходят план CLI.
        let arp = ReadyPlan::new_cli(eff("198.18.2.0/30", "I:2", |_| {}), nics(1)).unwrap();
        assert!(arp.is_arp_scan());
        ReadyPlan::new_cli(eff("198.18.2.0/30", "80,443,1000-1002", |_| {}), nics(1)).unwrap();
        ReadyPlan::new_cli(eff("198.18.2.0/30", "80,U:53,U:59999,I:0", |_| {}), nics(1)).unwrap();
        ReadyPlan::new_cli(
            eff("198.18.2.0/30", "80,S:2905,S:1,S:65535", |_| {}),
            nics(1),
        )
        .unwrap();
        // постоянный отказ сильнее остальных
        assert_eq!(
            cli_err("S:2905,O:47"),
            PlanError::OprotoNotSupported(196_911)
        );
        // 4 кадра ARP: 42 байта, адресат ff..ff, tpa пробегает цели
        let mut cur = arp.cursor_for_nic(0, None).unwrap();
        let frames = drain(&mut cur);
        assert!(cur.build_error().is_none());
        assert_eq!(frames.len(), 4);
        assert!(
            frames
                .iter()
                .all(|p| p.frame.len() == 42 && p.port_them == 0)
        );
        // без проверки портов (тестовый вход) порт без построителя (I:1) бьёт посреди прохода, а не заканчивает
        // скан естественно
        let plan =
            ReadyPlan::new_cli_without_port_checks(eff("198.18.2.0/30", "80,I:1", |_| {}), nics(1))
                .unwrap();
        let mut cur = plan.cursor_for_nic(0, None).unwrap();
        assert!(cur.build_error().is_none());
        let sent = drain(&mut cur).len();
        assert!(sent < 8, "sent {sent}");
        // конец не естественный: причина хранится и называет порт
        let e = cur.build_error().expect("failure must be recorded");
        assert!(matches!(e, PlanError::ProbeBuild(_)), "{e:?}");
        assert!(e.to_string().contains("does not fit TCP"), "{e}");
    }

    /// Независимая проверка кадра SCTP INIT: сумма IP, CRC-32C (побитово, без таблицы), длины, порты и поля INIT.
    fn check_sctp_frame(p: &Probe) {
        let f = &p.frame;
        assert_eq!(f.len(), 66);
        assert_eq!(f[23], 132, "proto SCTP");
        assert_eq!(crate::checksum::ip_header_checksum(f, 14, 34), 0xffff);
        assert_eq!(u16::from_be_bytes([f[16], f[17]]), 52);
        assert_eq!(&f[34..36], &p.port_me.to_be_bytes());
        assert_eq!(&f[36..38], &p.port_them.to_be_bytes());
        assert_eq!(&f[38..42], &[0; 4], "vtag 0");
        assert_eq!(&f[46..50], &[1, 0, 0, 0x14]);
        assert_eq!(&f[50..54], &p.seqno.to_be_bytes(), "initiate_tag = seqno");
        let mut z = f[34..].to_vec();
        z[8..12].fill(0);
        let mut crc = !0u32;
        for &b in &z {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82F6_3B78
                } else {
                    crc >> 1
                };
            }
        }
        assert_eq!(&f[42..46], &(!crc).to_le_bytes());
    }

    #[test]
    fn sctp_plan_builds_init_frames_and_splits_across_nics() {
        // S:2905 и S:1 через путь CLI: 66-байтовый INIT, cookie по индексу Templ_SCTP + порт (main.c:389).
        let e = || eff("198.18.2.0/30", "S:2905,S:1,S:65535", |_| {});
        let one = ReadyPlan::new_cli(e(), nics(1)).unwrap();
        let mut cur = one.cursor_for_nic(0, None).unwrap();
        let all = drain(&mut cur);
        assert!(cur.build_error().is_none());
        assert_eq!(all.len(), 12);
        for p in &all {
            check_sctp_frame(p);
            assert_eq!(p.port_index, TEMPL_SCTP + u32::from(p.port_them));
            let cookie = syn_cookie_ipv4(
                p.ip_them,
                p.port_index,
                p.ip_me,
                u32::from(p.port_me),
                0x1234_5678,
            ) as u32;
            assert_eq!(
                p.seqno, cookie,
                "seqno is the cookie over Templ_SCTP + port"
            );
            let ip_id = (p.ip_them ^ u32::from(p.port_them) ^ p.seqno) as u16;
            assert_eq!(&p.frame[18..20], &ip_id.to_be_bytes());
        }
        for port in [2905u16, 1, 65535] {
            assert_eq!(all.iter().filter(|p| p.port_them == port).count(), 4);
        }
        let two = ReadyPlan::new_cli(e(), nics(2)).unwrap();
        let k0 = drain(&mut two.cursor_for_nic(0, None).unwrap());
        let k1 = drain(&mut two.cursor_for_nic(1, None).unwrap());
        assert_eq!(k0.len() + k1.len(), 12);
        let mut merged: Vec<_> = k0.iter().chain(&k1).collect();
        merged.sort_by_key(|p| p.index);
        assert_eq!(
            merged.iter().map(|p| &p.frame).collect::<Vec<_>>(),
            all.iter().map(|p| &p.frame).collect::<Vec<_>>(),
            "the split reproduces the single stream"
        );
        // Смешанный список: TCP, UDP, SCTP и ICMP в одном потоке без ошибок сборки.
        let mixed = ReadyPlan::new_cli(eff("198.18.2.0/30", "80,U:53,S:2905,I:0", |_| {}), nics(1))
            .unwrap();
        let mut cur = mixed.cursor_for_nic(0, None).unwrap();
        let frames = drain(&mut cur);
        assert!(cur.build_error().is_none());
        for (len, n) in [(58, 4), (73, 4), (66, 4), (90, 4)] {
            assert_eq!(
                frames.iter().filter(|p| p.frame.len() == len).count(),
                n,
                "{len}"
            );
        }
    }

    /// Независимая проверка кадра UDP: сумма IP, сумма UDP (RFC 768), длины и порты.
    fn check_udp_frame(p: &Probe) {
        use crate::checksum::{ip_header_checksum, word_sum};
        let f = &p.frame;
        assert_eq!(f[23], 17, "proto UDP");
        assert_eq!(ip_header_checksum(f, 14, 34), 0xffff);
        assert_eq!(u16::from_be_bytes([f[16], f[17]]) as usize, f.len() - 14);
        assert_eq!(u16::from_be_bytes([f[38], f[39]]) as usize, f.len() - 34);
        assert_eq!(&f[34..36], &p.port_me.to_be_bytes());
        assert_eq!(&f[36..38], &p.port_them.to_be_bytes());
        let sum = 17 + (f.len() - 34) as u64 + word_sum(&f[26..34]) + word_sum(&f[34..]);
        assert_eq!(crate::checksum::fold(sum), 0xffff);
    }

    #[test]
    fn udp_plan_builds_frames_with_payloads_and_splits_across_nics() {
        // U:53 (DNS, 73 байта с cookie в txid) и U:59999 (нет в таблице, 42 байта) через путь CLI.
        let e = || eff("198.18.2.0/30", "U:53,U:59999", |_| {});
        let one = ReadyPlan::new_cli(e(), nics(1)).unwrap();
        let all = drain(&mut one.cursor_for_nic(0, None).unwrap());
        assert_eq!(all.len(), 8);
        for p in &all {
            check_udp_frame(p);
            assert_eq!(p.port_index, 65536 + u32::from(p.port_them));
            let cookie = syn_cookie_ipv4(
                p.ip_them,
                p.port_index,
                p.ip_me,
                u32::from(p.port_me),
                0x1234_5678,
            ) as u32;
            assert_eq!(p.seqno, cookie, "seqno is the cookie over Templ_UDP + port");
            let ip_id = (p.ip_them ^ u32::from(p.port_them) ^ p.seqno) as u16;
            assert_eq!(&p.frame[18..20], &ip_id.to_be_bytes());
            match p.port_them {
                53 => {
                    assert_eq!(p.frame.len(), 73);
                    assert_eq!(
                        &p.frame[42..44],
                        &(p.seqno as u16).to_be_bytes(),
                        "DNS txid"
                    );
                }
                59999 => assert_eq!(p.frame.len(), 42),
                other => panic!("port {other}"),
            }
        }
        assert_eq!(all.iter().filter(|p| p.port_them == 53).count(), 4);
        let two = ReadyPlan::new_cli(e(), nics(2)).unwrap();
        let k0 = drain(&mut two.cursor_for_nic(0, None).unwrap());
        let k1 = drain(&mut two.cursor_for_nic(1, None).unwrap());
        assert_eq!(k0.len() + k1.len(), 8);
        assert_eq!(
            k0.iter().map(|p| p.index).collect::<Vec<_>>(),
            [0, 2, 4, 6],
            "even outer indices"
        );
        let mut merged: Vec<_> = k0.iter().chain(&k1).collect();
        merged.sort_by_key(|p| p.index);
        assert_eq!(
            merged.iter().map(|p| &p.frame).collect::<Vec<_>>(),
            all.iter().map(|p| &p.frame).collect::<Vec<_>>(),
            "same source address on both test NICs: the split reproduces the single stream"
        );
        // Смешанный список: TCP, UDP и ICMP в одном потоке без ошибок сборки.
        let mixed =
            ReadyPlan::new_cli(eff("198.18.2.0/30", "80,U:53,I:0", |_| {}), nics(1)).unwrap();
        let mut cur = mixed.cursor_for_nic(0, None).unwrap();
        let frames = drain(&mut cur);
        assert!(cur.build_error().is_none());
        for (len, n) in [(58, 4), (73, 4), (90, 4)] {
            assert_eq!(
                frames.iter().filter(|p| p.frame.len() == len).count(),
                n,
                "{len}"
            );
        }
        let tcp = frames.iter().find(|p| p.frame.len() == 58).unwrap();
        assert_eq!(tcp.port_index, u32::from(tcp.port_them));
        let icmp = frames.iter().find(|p| p.frame.len() == 90).unwrap();
        assert_eq!(icmp.port_index, TEMPL_ICMP_ECHO);
    }

    #[test]
    fn udp_payload_table_from_files_reaches_the_frames() {
        use crate::payloads::PayloadTable;
        let mut table = PayloadTable::builtin();
        table
            .load_nmap_payloads("udp 59999\n\"hi\"\nudp 53\n\"x\"\n")
            .unwrap();
        let plan = ReadyPlan::new_cli_with_payloads(
            eff("198.18.2.0/30", "U:53,U:59999,U:161", |_| {}),
            nics(1),
            table.clone(),
        )
        .unwrap();
        let all = drain(&mut plan.cursor_for_nic(0, None).unwrap());
        assert_eq!(all.len(), 12);
        for p in &all {
            check_udp_frame(p);
            match p.port_them {
                59999 => assert_eq!(&p.frame[42..], b"hi"),
                53 => assert_eq!(&p.frame[42..], b"x", "file replaces the built-in DNS probe"),
                161 => assert_eq!(p.frame.len(), 42 + 59),
                other => panic!("port {other}"),
            }
        }
        // План помнит таблицу: RX-потоки адаптеров пересоздают план через неё.
        assert_eq!(plan.payloads().len(), table.len());
        // Оракул без сети строит те же кадры.
        let mut oracle_frames = Vec::new();
        let flow = for_each_probe_nic_with_payloads(
            &eff("198.18.2.0/30", "U:53,U:59999,U:161", |_| {}),
            &nics(1)[0],
            &table,
            |p| {
                oracle_frames.push(p.frame.clone());
                ControlFlow::<()>::Continue(())
            },
        )
        .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(
            oracle_frames,
            all.iter().map(|p| p.frame.clone()).collect::<Vec<_>>()
        );
    }

    // ---- IPv6 stage, Task 2: the IPv4 order must not move --------------------------------------

    /// FNV-1a 64, the hash the vector below was captured with.
    fn fnv1a(h: &mut u64, bytes: &[u8]) {
        for b in bytes {
            *h ^= u64::from(*b);
            *h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    /// Review Focus 2. The constants below were captured from the code at the
    /// Task 2 BASE (68c0e2e, before any change of this task) with the same
    /// scenario: `198.18.0.0/28`, ports `80,443`, `seed = 42`, default rounds (14)
    /// and rate (100), adapter `10.255.0.1` / `00:11:22:33:44:55` -> `66:55:44:33:22:11`,
    /// source ports 40000-40003. `PROBES` is `(index, ip_them, port_them)` of
    /// `for_each_probe`; `FRAME_HASH` is FNV-1a 64 over, per probe, little-endian
    /// u64 of `index, ip_me, port_me, ip_them, port_them, port_index, seqno` then
    /// the frame bytes; `TRANSMIT` is `(i, repeats, xXx, ip, port)` of
    /// `transmit_scan`; `LIST` is `(ip, port)` of `list_scan`. With no IPv6 target
    /// every index, probe and frame stays byte-identical (main.c:258-260: range_ipv6 == 0).
    #[test]
    fn pure_ipv4_sequence_unchanged_with_ipv6_support() {
        const PROBES: [(u64, u32, u16); 32] = [
            (0, 0xc612000d, 443),
            (1, 0xc612000f, 80),
            (2, 0xc6120000, 80),
            (3, 0xc6120007, 80),
            (4, 0xc6120008, 80),
            (5, 0xc612000b, 80),
            (6, 0xc6120005, 80),
            (7, 0xc6120006, 80),
            (8, 0xc612000e, 80),
            (9, 0xc6120007, 443),
            (10, 0xc6120009, 80),
            (11, 0xc6120001, 80),
            (12, 0xc6120009, 443),
            (13, 0xc6120006, 443),
            (14, 0xc6120008, 443),
            (15, 0xc612000f, 443),
            (16, 0xc6120002, 80),
            (17, 0xc612000c, 443),
            (18, 0xc6120001, 443),
            (19, 0xc612000e, 443),
            (20, 0xc6120000, 443),
            (21, 0xc612000a, 80),
            (22, 0xc6120002, 443),
            (23, 0xc6120003, 80),
            (24, 0xc612000c, 80),
            (25, 0xc612000d, 80),
            (26, 0xc6120004, 443),
            (27, 0xc6120003, 443),
            (28, 0xc612000a, 443),
            (29, 0xc612000b, 443),
            (30, 0xc6120005, 443),
            (31, 0xc6120004, 80),
        ];
        const FRAME_HASH: u64 = 0x205e28f8c5c6f857;
        const TRANSMIT: [(u64, u64, u64, u32, u32); 32] = [
            (0, 0, 29, 0xc612000d, 443),
            (1, 0, 15, 0xc612000f, 80),
            (2, 0, 0, 0xc6120000, 80),
            (3, 0, 7, 0xc6120007, 80),
            (4, 0, 8, 0xc6120008, 80),
            (5, 0, 11, 0xc612000b, 80),
            (6, 0, 5, 0xc6120005, 80),
            (7, 0, 6, 0xc6120006, 80),
            (8, 0, 14, 0xc612000e, 80),
            (9, 0, 23, 0xc6120007, 443),
            (10, 0, 9, 0xc6120009, 80),
            (11, 0, 1, 0xc6120001, 80),
            (12, 0, 25, 0xc6120009, 443),
            (13, 0, 22, 0xc6120006, 443),
            (14, 0, 24, 0xc6120008, 443),
            (15, 0, 31, 0xc612000f, 443),
            (16, 0, 2, 0xc6120002, 80),
            (17, 0, 28, 0xc612000c, 443),
            (18, 0, 17, 0xc6120001, 443),
            (19, 0, 30, 0xc612000e, 443),
            (20, 0, 16, 0xc6120000, 443),
            (21, 0, 10, 0xc612000a, 80),
            (22, 0, 18, 0xc6120002, 443),
            (23, 0, 3, 0xc6120003, 80),
            (24, 0, 12, 0xc612000c, 80),
            (25, 0, 13, 0xc612000d, 80),
            (26, 0, 20, 0xc6120004, 443),
            (27, 0, 19, 0xc6120003, 443),
            (28, 0, 26, 0xc612000a, 443),
            (29, 0, 27, 0xc612000b, 443),
            (30, 0, 21, 0xc6120005, 443),
            (31, 0, 4, 0xc6120004, 80),
        ];
        const LIST: [(u32, u32); 32] = [
            (0xc612000a, 443),
            (0xc612000b, 443),
            (0xc6120005, 443),
            (0xc6120004, 80),
            (0xc612000d, 443),
            (0xc612000f, 80),
            (0xc6120000, 80),
            (0xc6120007, 80),
            (0xc6120008, 80),
            (0xc612000b, 80),
            (0xc6120005, 80),
            (0xc6120006, 80),
            (0xc612000e, 80),
            (0xc6120007, 443),
            (0xc6120009, 80),
            (0xc6120001, 80),
            (0xc6120009, 443),
            (0xc6120006, 443),
            (0xc6120008, 443),
            (0xc612000f, 443),
            (0xc6120002, 80),
            (0xc612000c, 443),
            (0xc6120001, 443),
            (0xc612000e, 443),
            (0xc6120000, 443),
            (0xc612000a, 80),
            (0xc6120002, 443),
            (0xc6120003, 80),
            (0xc612000c, 80),
            (0xc612000d, 80),
            (0xc6120004, 443),
            (0xc6120003, 443),
        ];
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), "198.18.0.0/28").unwrap();
        parse_ports(m.ports_mut(), "80,443").unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed: 42,
            ..ScanConfig::default()
        };
        let e = validate(&cfg, Operation::Scan).unwrap();
        assert!(!e.massip().has_ipv6_targets());
        let (mut h, mut got) = (0xcbf2_9ce4_8422_2325u64, Vec::new());
        let flow = for_each_probe(&e, &binding(), |p| {
            assert_eq!(p.target, TargetIp::V4(p.ip_them));
            for v in [
                p.index,
                u64::from(p.ip_me),
                u64::from(p.port_me),
                u64::from(p.ip_them),
                u64::from(p.port_them),
                u64::from(p.port_index),
                u64::from(p.seqno),
            ] {
                fnv1a(&mut h, &v.to_le_bytes());
            }
            fnv1a(&mut h, &p.frame);
            got.push((p.index, p.ip_them, p.port_them));
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(got, PROBES);
        assert_eq!(h, FRAME_HASH);
        // the runtime cursor yields the same probes, frame for frame
        let plan = ReadyPlan::new_cli(e.clone(), nics(1)).unwrap();
        let from_cursor = drain(&mut plan.cursor_for_nic(0, None).unwrap());
        assert_eq!(from_cursor, oracle(&e));
        let mut hc = 0xcbf2_9ce4_8422_2325u64;
        for p in &from_cursor {
            for v in [
                p.index,
                u64::from(p.ip_me),
                u64::from(p.port_me),
                u64::from(p.ip_them),
                u64::from(p.port_them),
                u64::from(p.port_index),
                u64::from(p.seqno),
            ] {
                fnv1a(&mut hc, &v.to_le_bytes());
            }
            fnv1a(&mut hc, &p.frame);
        }
        assert_eq!(hc, FRAME_HASH);
        // the index streams the probes come from
        let mut tr = Vec::new();
        crate::scan::transmit_scan(
            e.massip(),
            e.seed(),
            e.blackrock_rounds(),
            e.shard(),
            1,
            0,
            e.resume_index(),
            e.resume_count(),
            e.retries(),
            e.max_rate(),
            |i, rep, x, ip, port| tr.push((i, rep, x, ip, port)),
        )
        .unwrap();
        assert_eq!(tr, TRANSMIT);
        let mut ls = Vec::new();
        crate::scan::list_scan(
            e.massip(),
            e.seed(),
            e.blackrock_rounds(),
            e.shard(),
            0,
            None,
            0,
            e.max_rate(),
            |ip, port| ls.push((ip, port)),
        )
        .unwrap();
        assert_eq!(ls, LIST);
    }

    fn eff_v46(targets: &str, ports: &str) -> EffectiveConfig {
        eff_v46_seed(targets, ports, 42)
    }

    fn eff_v46_seed(targets: &str, ports: &str, seed: u64) -> EffectiveConfig {
        let mut m = MassIp::new();
        m.add_target_string(targets).unwrap();
        parse_ports(m.ports_mut(), ports).unwrap();
        let cfg = ScanConfig {
            targets: m,
            seed,
            ..ScanConfig::default()
        };
        validate(&cfg, Operation::Scan).unwrap()
    }

    /// R7: a plan with an IPv6 target is refused before any frame, on every way in
    /// (Studio `new`, CLI `new_cli`, the streaming oracle). IPv4 targets in the same
    /// plan do not rescue it: that would silently drop the IPv6 half.
    #[test]
    fn plans_and_oracle_refuse_ipv6_targets_never_skip_them() {
        for t in ["2001:db8::10", "2001:db8::10,198.18.0.1"] {
            let e = eff_v46(t, "80");
            assert_eq!(
                ReadyPlan::new(e.clone(), binding()).unwrap_err(),
                PlanError::Ipv6TargetsNotSupported,
                "{t}"
            );
            assert_eq!(
                ReadyPlan::new_cli(e.clone(), nics(1)).unwrap_err(),
                PlanError::Ipv6TargetsNotSupported,
                "{t}"
            );
            let mut sent = 0;
            let r = for_each_probe(&e, &binding(), |_| {
                sent += 1;
                ControlFlow::<()>::Continue(())
            });
            assert_eq!(r.unwrap_err(), PlanError::Scan(ScanError::Ipv6Targets));
            assert_eq!(sent, 0);
        }
    }

    /// IPv6 stage, Task 3 (main.c:336-353): цель IPv6 берёт `ip_me = src.ipv6` и `port_me = src.port` (первый
    /// порт, без ротации), `cookie = syn_cookie_ipv6`, `seqno = (unsigned)cookie`. Кадр и cookie напечатаны
    /// настоящим C (`syn_cookie_ipv6` + `template_set_target_ipv6`, seqno 0x824e4617 это младшие 32 бита
    /// 0x8edac6d1824e4617). `for_each_probe` по-прежнему отказывает IPv6 (R7); этот путь открывает T5.
    #[test]
    fn probe_v6_frame_and_seqno_match_c() {
        const THEM: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0001;
        const ME: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0002;
        let mut b = binding();
        b.link_type = LinkType::Ethernet;
        b.source_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        b.next_hop_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
        b.source_ports = (40000, 40015);
        let nic = NicBinding {
            binding: b,
            source_ipv4_last: 0,
            legacy_c_17_port_mask: false,
            source_ipv6: Some(ME),
        };
        let nic = NicBinding {
            source_ipv4_last: nic.binding.source_ipv4,
            ..nic
        };
        let e = eff_v46_seed("2001:db8::1", "80", 0x0123_4567_89ab_cdef);
        let plan = ReadyPlan::new_cli_without_ipv6_guard(e, vec![nic.clone()]).unwrap();
        let p = plan.probe_v6(0, 7, THEM, 80).unwrap();
        assert_eq!(p.seqno, 0x824e_4617);
        assert_eq!((p.port_me, p.port_them, p.port_index), (40000, 80, 80));
        assert_eq!(p.target, TargetIp::V6(THEM));
        assert_eq!((p.ip_me, p.ip_them), (0, 0));
        assert_eq!(p.index, 7);
        let c = "aabbccddee02 021122334455 86dd 60000000 0018 06 ff fd00000000000000 0000000000000002 \
                 20010db800000000 0000000000000001 9c40 0050 824e4617 00000000 6002 0401 0473 0000 020405b4";
        let want: Vec<u8> = {
            let h: String = c.split_whitespace().collect();
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect()
        };
        assert_eq!(p.frame, want);
        // Не TCP-порт поверх IPv6 это R3, а не молчаливый кадр.
        assert_eq!(
            plan.probe_v6(0, 0, THEM, TEMPL_UDP + 53).unwrap_err(),
            PlanError::PortNotTcp(TEMPL_UDP + 53)
        );
        // Нет source_ipv6: отказ, а не кадр с нулевым источником.
        let mut none = nic;
        none.source_ipv6 = None;
        let plan_none =
            ReadyPlan::new_cli_without_ipv6_guard(eff_v46("2001:db8::1", "80"), vec![none])
                .unwrap();
        assert_eq!(
            plan_none.probe_v6(0, 0, THEM, 80).unwrap_err(),
            PlanError::NoSourceIpv6
        );
        // Индекс адаптера вне плана.
        assert_eq!(
            plan.probe_v6(1, 0, THEM, 80).unwrap_err(),
            PlanError::NicIndexOutOfRange { index: 1, count: 1 }
        );
    }
}
